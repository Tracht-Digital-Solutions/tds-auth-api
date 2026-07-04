<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action\Admin\Users;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\Admin\Users\CreateUserAction;
use Tds\AuthApi\Action\Admin\Users\DeleteUserAction;
use Tds\AuthApi\Action\Admin\Users\ListUsersAction;
use Tds\AuthApi\Action\Admin\Users\ResetPasswordAction;
use Tds\AuthApi\Action\Admin\Users\UpdateUserAction;
use Tds\AuthApi\Domain\AppUser;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\PasswordGenerator;
use Tds\AuthApi\Tests\Support\FakeAppUserRepository;
use Tds\AuthApi\Tests\Support\FakeSessionRepository;

final class UsersActionsTest extends TestCase
{
    private FakeAppUserRepository $users;
    private FakeSessionRepository $sessions;
    private PasswordGenerator $passwords;

    protected function setUp(): void
    {
        $this->users = new FakeAppUserRepository();
        $this->sessions = new FakeSessionRepository();
        $this->passwords = new PasswordGenerator();
    }

    // ---- create ----------------------------------------------------------

    public function test_create_with_generated_password_returns_temp(): void
    {
        $response = $this->create(['email' => 'new@example.com', 'customerId' => 4, 'permissions' => ['invoices:read', 'invoices:delete']]);

        self::assertSame(201, $response->getStatusCode());
        $body = $this->jsonBody($response);
        self::assertArrayHasKey('tempPassword', $body);
        self::assertSame('new@example.com', $body['user']['email']);
        self::assertSame(4, $body['user']['customerId']);
        // Unknown permission key was dropped.
        self::assertSame(['invoices:read'], $body['user']['permissions']);
    }

    public function test_create_with_provided_password_omits_temp(): void
    {
        $body = $this->jsonBody($this->create(['email' => 'a@example.com', 'password' => 'a-strong-password']));
        self::assertArrayNotHasKey('tempPassword', $body);
    }

    public function test_create_admin_support_agent(): void
    {
        $body = $this->jsonBody($this->create([
            'email' => 'agent@example.com',
            'isAdmin' => true,
            'isSupportAgent' => true,
        ]));
        self::assertTrue($body['user']['isAdmin']);
        self::assertTrue($body['user']['isSupportAgent']);
    }

    public function test_create_ignores_support_agent_for_non_admin(): void
    {
        $body = $this->jsonBody($this->create([
            'email' => 'cust@example.com',
            'isAdmin' => false,
            'isSupportAgent' => true,
        ]));
        self::assertFalse($body['user']['isAdmin']);
        self::assertFalse($body['user']['isSupportAgent']);
    }

    public function test_create_rejects_duplicate_email(): void
    {
        $this->users->seed(new AppUser(1, 'dup@example.com', null, false, 1, [], 'active', 'x'));
        self::assertSame(409, $this->create(['email' => 'dup@example.com'])->getStatusCode());
    }

    public function test_create_rejects_invalid_email(): void
    {
        self::assertSame(422, $this->create(['email' => 'nope'])->getStatusCode());
    }

    // ---- list ------------------------------------------------------------

    public function test_list_filters_by_customer(): void
    {
        $this->users->seed(new AppUser(1, 'a@example.com', null, false, 10, [], 'active', 'x'));
        $this->users->seed(new AppUser(2, 'b@example.com', null, false, 20, [], 'active', 'x'));

        $request = (new ServerRequestFactory())->createServerRequest('GET', '/admin/users')
            ->withQueryParams(['customer_id' => '10']);
        $response = (new ListUsersAction($this->users))($request, new Response());

        $body = $this->jsonBody($response);
        self::assertCount(1, $body['users']);
        self::assertSame('a@example.com', $body['users'][0]['email']);
    }

    // ---- update ----------------------------------------------------------

    public function test_update_toggles_admin_and_revokes_sessions(): void
    {
        $this->users->seed(new AppUser(5, 'u@example.com', null, false, 7, ['invoices:read'], 'active', 'x'));

        $response = $this->update(5, ['isAdmin' => true], actingUid: 1);

        self::assertSame(200, $response->getStatusCode());
        self::assertTrue($this->jsonBody($response)['user']['isAdmin']);
        self::assertContains(5, $this->sessions->revokedUsers);
    }

    public function test_update_missing_user_returns_404(): void
    {
        self::assertSame(404, $this->update(999, ['name' => 'X'], actingUid: 1)->getStatusCode());
    }

    public function test_update_sets_support_agent_and_revokes_sessions(): void
    {
        $this->users->seed(new AppUser(5, 'a@example.com', null, true, null, [], 'active', 'x'));

        $response = $this->update(5, ['isSupportAgent' => true], actingUid: 1);

        self::assertSame(200, $response->getStatusCode());
        self::assertTrue($this->jsonBody($response)['user']['isSupportAgent']);
        self::assertContains(5, $this->sessions->revokedUsers);
    }

    public function test_update_support_agent_ignored_for_non_admin(): void
    {
        $this->users->seed(new AppUser(5, 'c@example.com', null, false, 7, [], 'active', 'x'));

        $response = $this->update(5, ['isSupportAgent' => true], actingUid: 1);

        self::assertFalse($this->jsonBody($response)['user']['isSupportAgent']);
    }

    public function test_update_demoting_admin_clears_support_agent(): void
    {
        $this->users->seed(new AppUser(5, 'a@example.com', null, true, null, [], 'active', 'x', false, true));

        $response = $this->update(5, ['isAdmin' => false], actingUid: 1);

        $body = $this->jsonBody($response);
        self::assertFalse($body['user']['isAdmin']);
        self::assertFalse($body['user']['isSupportAgent']);
    }

    public function test_update_self_cannot_drop_admin(): void
    {
        $this->users->seed(new AppUser(1, 'me@example.com', null, true, null, [], 'active', 'x'));

        $response = $this->update(1, ['isAdmin' => false], actingUid: 1);

        self::assertSame(409, $response->getStatusCode());
    }

    public function test_update_self_cannot_disable(): void
    {
        $this->users->seed(new AppUser(1, 'me@example.com', null, true, null, [], 'active', 'x'));

        self::assertSame(409, $this->update(1, ['status' => 'disabled'], actingUid: 1)->getStatusCode());
    }

    // ---- delete ----------------------------------------------------------

    public function test_delete_removes_user_and_revokes(): void
    {
        $this->users->seed(new AppUser(5, 'u@example.com', null, false, 7, [], 'active', 'x'));

        $response = $this->delete(5, actingUid: 1);

        self::assertSame(204, $response->getStatusCode());
        self::assertNull($this->users->findById(5));
        self::assertContains(5, $this->sessions->revokedUsers);
    }

    public function test_delete_self_returns_409(): void
    {
        $this->users->seed(new AppUser(1, 'me@example.com', null, true, null, [], 'active', 'x'));
        self::assertSame(409, $this->delete(1, actingUid: 1)->getStatusCode());
    }

    public function test_delete_missing_returns_404(): void
    {
        self::assertSame(404, $this->delete(999, actingUid: 1)->getStatusCode());
    }

    // ---- reset password --------------------------------------------------

    public function test_reset_password_returns_temp_and_revokes(): void
    {
        $this->users->seed(new AppUser(5, 'u@example.com', null, false, 7, [], 'active', 'oldhash'));

        $request = (new ServerRequestFactory())->createServerRequest('POST', '/admin/users/5/reset-password');
        $response = (new ResetPasswordAction($this->users, $this->sessions, $this->passwords))($request, new Response(), ['id' => '5']);

        self::assertSame(200, $response->getStatusCode());
        self::assertArrayHasKey('tempPassword', $this->jsonBody($response));
        self::assertContains(5, $this->sessions->revokedUsers);
        self::assertNotSame('oldhash', $this->users->findById(5)?->passwordHash);
    }

    // ---- helpers ---------------------------------------------------------

    /** @param array<string,mixed> $body */
    private function create(array $body): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('POST', '/admin/users')->withParsedBody($body);
        return (new CreateUserAction($this->users, $this->passwords))($request, new Response());
    }

    /** @param array<string,mixed> $body */
    private function update(int $id, array $body, int $actingUid): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('PATCH', '/admin/users/' . $id)
            ->withAttribute(JwtAuthMiddleware::ATTR_CLAIMS, ['uid' => $actingUid, 'admin' => true])
            ->withParsedBody($body);
        return (new UpdateUserAction($this->users, $this->sessions))($request, new Response(), ['id' => (string) $id]);
    }

    private function delete(int $id, int $actingUid): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('DELETE', '/admin/users/' . $id)
            ->withAttribute(JwtAuthMiddleware::ATTR_CLAIMS, ['uid' => $actingUid, 'admin' => true]);
        return (new DeleteUserAction($this->users, $this->sessions))($request, new Response(), ['id' => (string) $id]);
    }

    /** @return array<string,mixed> */
    private function jsonBody(ResponseInterface $response): array
    {
        $response->getBody()->rewind();
        return json_decode($response->getBody()->getContents(), true);
    }
}
