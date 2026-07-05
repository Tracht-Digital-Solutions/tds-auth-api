<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\ChangePasswordAction;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Tests\Support\FakeAppUserRepository;
use Tds\AuthApi\Tests\Support\FakeSessionRepository;
use Tds\AuthApi\Tests\Support\Keys;

final class ChangePasswordActionTest extends TestCase
{
    private FakeAppUserRepository $users;
    private JwtService $jwt;
    private FakeSessionRepository $sessions;
    private CookieFactory $cookies;

    protected function setUp(): void
    {
        $this->users = new FakeAppUserRepository();
        $keys = new Keys();
        $this->jwt = new JwtService(
            privateKeyPem: $keys->privatePem,
            publicKeyPem: $keys->publicPem,
            keyId: 'kid',
            issuer: 'tds-auth-api-test',
            ttlSeconds: 900,
            refreshTtlSeconds: 86400,
        );
        $this->sessions = new FakeSessionRepository();
        $this->cookies = new CookieFactory('tds_session', '.local', secure: false);
    }

    private function seed(string $password): int
    {
        return $this->users->create(
            'user@example.com',
            password_hash($password, PASSWORD_ARGON2ID),
            'User',
            false,
            7,
            ['invoices:read'],
            'active',
        );
    }

    public function test_missing_fields_returns_400(): void
    {
        $id = $this->seed('old-password-123');
        self::assertSame(400, $this->change($id, ['old' => '', 'new' => ''])->getStatusCode());
    }

    public function test_short_new_password_returns_422(): void
    {
        $id = $this->seed('old-password-123');
        self::assertSame(422, $this->change($id, ['old' => 'old-password-123', 'new' => 'short'])->getStatusCode());
    }

    public function test_wrong_old_password_returns_401(): void
    {
        $id = $this->seed('old-password-123');
        self::assertSame(401, $this->change($id, ['old' => 'nope-nope-nope', 'new' => 'new-password-456'])->getStatusCode());
    }

    public function test_happy_path_revokes_all_sessions_and_rehashes(): void
    {
        $id = $this->seed('old-password-123');
        // Two "other device" sessions plus the caller's own session.
        $this->sessions->record('other-1', 7, false, time() + 900, $id);
        $this->sessions->record('other-2', 7, false, time() + 900, $id);
        $oldJti = 'old-jti';
        $this->sessions->record($oldJti, 7, false, time() + 900, $id);

        $response = $this->change($id, ['old' => 'old-password-123', 'new' => 'new-password-456'], $oldJti);

        self::assertSame(200, $response->getStatusCode());
        // Every pre-existing session for the user is terminated — not just the
        // caller's jti — so a lost/stolen device can't keep refreshing.
        self::assertContains($id, $this->sessions->revokedUsers, 'all user sessions must be revoked');
        self::assertTrue($this->sessions->isRevoked('other-1'));
        self::assertTrue($this->sessions->isRevoked('other-2'));
        self::assertTrue($this->sessions->isRevoked($oldJti));

        // New password verifies against the stored hash.
        $user = $this->users->findById($id);
        self::assertNotNull($user);
        self::assertTrue(password_verify('new-password-456', $user->passwordHash));

        // The caller keeps a fresh, live session so they stay logged in here.
        self::assertNotEmpty($this->sessions->listActive(), 'a fresh session survives for the caller');
    }

    public function test_clears_must_change_password_flag(): void
    {
        $id = $this->seed('temp-password-123');
        $this->users->update($id, ['must_change_password' => true]);
        self::assertTrue($this->users->findById($id)?->mustChangePassword);

        $response = $this->change($id, ['old' => 'temp-password-123', 'new' => 'chosen-password-456']);

        self::assertSame(200, $response->getStatusCode());
        self::assertFalse($this->users->findById($id)?->mustChangePassword, 'flag must be cleared');
    }

    public function test_unknown_user_revokes_and_returns_401(): void
    {
        $response = $this->change(999, ['old' => 'whatever-1234', 'new' => 'another-1234'], 'j');

        self::assertSame(401, $response->getStatusCode());
        self::assertContains('j', $this->sessions->revoked);
    }

    /** @param array<string,mixed> $body */
    private function change(int $uid, array $body, string $jti = 'jti-1'): ResponseInterface
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('PUT', '/password')
            ->withAttribute(JwtAuthMiddleware::ATTR_CLAIMS, ['uid' => $uid, 'jti' => $jti])
            ->withParsedBody($body);
        $action = new ChangePasswordAction($this->users, $this->jwt, $this->sessions, $this->cookies);
        return $action($request, new Response());
    }
}
