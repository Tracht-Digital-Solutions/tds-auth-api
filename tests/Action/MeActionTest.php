<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\MeAction;
use Tds\AuthApi\Domain\AppUser;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Tests\Support\FakeAppUserRepository;

final class MeActionTest extends TestCase
{
    private FakeAppUserRepository $users;

    protected function setUp(): void
    {
        $this->users = new FakeAppUserRepository();
    }

    public function test_returns_customer_principal(): void
    {
        $this->users->seed(new AppUser(3, 'cust@example.com', 'Cust', false, 7, ['invoices:read'], 'active', 'x'));

        $response = $this->me(['uid' => 3]);

        self::assertSame(200, $response->getStatusCode());
        $body = $this->jsonBody($response);
        self::assertSame(3, $body['userId']);
        self::assertFalse($body['isAdmin']);
        self::assertSame(7, $body['customerId']);
        self::assertSame(['invoices:read'], $body['permissions']);
    }

    public function test_admin_principal_has_empty_permissions(): void
    {
        $this->users->seed(new AppUser(1, 'admin@example.com', 'Admin', true, null, [], 'active', 'x'));

        $body = $this->jsonBody($this->me(['uid' => 1]));

        self::assertTrue($body['isAdmin']);
        self::assertSame([], $body['permissions']);
    }

    public function test_support_agent_flag_is_exposed_for_admins(): void
    {
        $this->users->seed(new AppUser(1, 'agent@example.com', 'Agent', true, null, [], 'active', 'x', false, true));

        $body = $this->jsonBody($this->me(['uid' => 1]));

        self::assertTrue($body['isAdmin']);
        self::assertTrue($body['isSupportAgent']);
    }

    public function test_support_agent_flag_never_leaks_to_non_admins(): void
    {
        // A stray flag on a non-admin row must not surface as a support agent.
        $this->users->seed(new AppUser(2, 'cust@example.com', 'Cust', false, 7, ['invoices:read'], 'active', 'x', false, true));

        $body = $this->jsonBody($this->me(['uid' => 2]));

        self::assertFalse($body['isAdmin']);
        self::assertFalse($body['isSupportAgent']);
    }

    public function test_unknown_user_returns_401(): void
    {
        self::assertSame(401, $this->me(['uid' => 999])->getStatusCode());
    }

    public function test_surfaces_session_expiry_from_the_exp_claim(): void
    {
        $this->users->seed(new AppUser(3, 'cust@example.com', 'Cust', false, 7, [], 'active', 'x'));

        $body = $this->jsonBody($this->me(['uid' => 3, 'exp' => 1893456000]));

        // The panels' inline gate reads this to bounce an expired session
        // before the panel paints.
        self::assertSame(1893456000, $body['expiresAt']);
    }

    public function test_expiry_is_null_when_the_claim_is_absent(): void
    {
        $this->users->seed(new AppUser(3, 'cust@example.com', 'Cust', false, 7, [], 'active', 'x'));

        $body = $this->jsonBody($this->me(['uid' => 3]));

        self::assertNull($body['expiresAt']);
    }

    /** @param array<string,mixed> $claims */
    private function me(array $claims): ResponseInterface
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', '/me')
            ->withAttribute(JwtAuthMiddleware::ATTR_CLAIMS, $claims);
        return (new MeAction($this->users))($request, new Response());
    }

    /** @return array<string,mixed> */
    private function jsonBody(ResponseInterface $response): array
    {
        $response->getBody()->rewind();
        return json_decode($response->getBody()->getContents(), true);
    }
}
