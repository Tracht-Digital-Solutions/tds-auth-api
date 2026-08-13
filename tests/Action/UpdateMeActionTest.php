<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\UpdateMeAction;
use Tds\AuthApi\Domain\AppUser;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Tests\Support\FakeAppUserRepository;

/**
 * `PATCH /me` is the only endpoint where a user writes to their own `app_user`
 * row, so its whitelist is a privilege boundary, not a convenience. Every test
 * that asserts a field is IGNORED is guarding that boundary: silently dropping
 * an unknown key is only safe as long as the drop actually happens.
 */
final class UpdateMeActionTest extends TestCase
{
    private FakeAppUserRepository $users;

    protected function setUp(): void
    {
        $this->users = new FakeAppUserRepository();
        $this->users->seed(new AppUser(
            id: 5,
            email: 'user@example.com',
            name: 'Julian Tracht',
            isAdmin: false,
            companyId: 7,
            permissions: ['tickets:read'],
            status: 'active',
            passwordHash: 'x',
        ));
    }

    public function test_sets_the_display_name(): void
    {
        $response = $this->patch(['displayName' => 'Julian']);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('Julian', $this->users->updates[5]['display_name']);
    }

    public function test_trims_and_truncates_to_the_column_width(): void
    {
        $this->patch(['displayName' => '  ' . str_repeat('a', 150) . '  ']);

        self::assertSame(100, mb_strlen((string) $this->users->updates[5]['display_name']));
    }

    public function test_empty_string_clears_it_rather_than_storing_blank(): void
    {
        // The label falls back to `name`, then the email, so the panel can
        // never end up rendering an empty header.
        $this->patch(['displayName' => '   ']);

        self::assertNull($this->users->updates[5]['display_name']);
    }

    public function test_null_clears_it_too(): void
    {
        $this->patch(['displayName' => null]);

        self::assertNull($this->users->updates[5]['display_name']);
    }

    public function test_rejects_a_non_string_display_name(): void
    {
        $response = $this->patch(['displayName' => ['nope']]);

        self::assertSame(422, $response->getStatusCode());
        self::assertSame([], $this->users->updates);
    }

    public function test_ignores_every_privileged_field(): void
    {
        // The whole point of the endpoint: a user may rename themselves in the
        // header and nothing else. If any of these ever reached `update()`,
        // self-service would be a privilege-escalation path.
        $this->patch([
            'displayName' => 'Julian',
            'isAdmin' => true,
            'isSupportAgent' => true,
            'isBlogAuthor' => true,
            'status' => 'disabled',
            'permissions' => ['invoices:pay'],
            'memberships' => [['customerId' => 99, 'permissions' => []]],
            'customerId' => 99,
            'email' => 'attacker@example.com',
            // `name` is excluded too: it drives the admin user list and the
            // public blog byline, which is not the same decision as picking a
            // nickname for your own header.
            'name' => 'Someone Else',
        ]);

        self::assertSame(['display_name' => 'Julian'], $this->users->updates[5]);
        // The seeded single-company membership is untouched — `memberships`
        // and `customerId` in the body reached nothing.
        self::assertSame(
            [7],
            array_column($this->users->membershipRows[5], 'companyId'),
        );
        self::assertSame(
            ['tickets:read'],
            $this->users->membershipRows[5][0]['permissions'],
        );
    }

    public function test_writes_nothing_when_the_body_names_no_known_field(): void
    {
        $response = $this->patch(['nickname' => 'Julian']);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame([], $this->users->updates);
    }

    public function test_never_revokes_sessions(): void
    {
        // Nothing here is authorization-relevant, so logging the user out of
        // every device for renaming themselves would be gratuitous. The action
        // has no SessionRepository at all — this asserts the constructor
        // signature stays that way.
        $reflection = new \ReflectionClass(UpdateMeAction::class);
        $params = $reflection->getConstructor()?->getParameters() ?? [];

        self::assertCount(1, $params);
    }

    public function test_unknown_user_returns_401(): void
    {
        $response = $this->patch(['displayName' => 'X'], uid: 999);

        self::assertSame(401, $response->getStatusCode());
    }

    /** @param array<string,mixed> $body */
    private function patch(array $body, int $uid = 5): ResponseInterface
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('PATCH', '/me')
            ->withAttribute(JwtAuthMiddleware::ATTR_CLAIMS, ['uid' => $uid])
            ->withParsedBody($body);

        return (new UpdateMeAction($this->users))($request, new Response());
    }
}
