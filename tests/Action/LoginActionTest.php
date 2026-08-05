<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\LoginAction;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Service\RememberCookieFactory;
use Tds\AuthApi\Service\RememberTokenService;
use Tds\AuthApi\Tests\Support\FakeAppUserRepository;
use Tds\AuthApi\Tests\Support\FakeRememberTokenRepository;
use Tds\AuthApi\Tests\Support\FakeRateLimiter;
use Tds\AuthApi\Tests\Support\FakeSessionRepository;
use Tds\AuthApi\Tests\Support\Keys;

final class LoginActionTest extends TestCase
{
    private FakeAppUserRepository $users;
    private JwtService $jwt;
    private FakeSessionRepository $sessions;
    private CookieFactory $cookies;
    private FakeRememberTokenRepository $rememberRepo;
    private RememberTokenService $remember;
    private RememberCookieFactory $rememberCookies;
    private FakeRateLimiter $rateLimiter;

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
        $this->rememberRepo = new FakeRememberTokenRepository();
        $this->remember = new RememberTokenService($this->rememberRepo, 2592000);
        $this->rememberCookies = new RememberCookieFactory(new CookieFactory('tds_remember', '.local', secure: false));
        $this->rateLimiter = new FakeRateLimiter();
    }

    private function seed(
        string $email,
        string $password,
        bool $isAdmin = false,
        ?int $customerId = 7,
        array $permissions = ['invoices:read'],
        string $status = 'active',
    ): int {
        return $this->users->create(
            $email,
            password_hash($password, PASSWORD_ARGON2ID),
            null,
            $isAdmin,
            $customerId,
            $permissions,
            $status,
        );
    }

    public function test_malformed_email_returns_400(): void
    {
        self::assertSame(400, $this->login(['email' => 'nope', 'password' => 'whatever'])->getStatusCode());
    }

    public function test_unknown_email_returns_401(): void
    {
        $response = $this->login(['email' => 'ghost@example.com', 'password' => 'whatever']);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(['error' => 'Invalid credentials'], $this->jsonBody($response));
    }

    public function test_wrong_password_returns_401(): void
    {
        $this->seed('user@example.com', 'correct-horse-battery');

        self::assertSame(401, $this->login(['email' => 'user@example.com', 'password' => 'wrong'])->getStatusCode());
    }

    public function test_disabled_account_returns_403_even_with_correct_password(): void
    {
        $this->seed('user@example.com', 'correct-horse-battery', status: 'disabled');

        $response = $this->login(['email' => 'user@example.com', 'password' => 'correct-horse-battery']);

        self::assertSame(403, $response->getStatusCode());
        self::assertSame([], $this->sessions->sessions, 'no session for a disabled account');
    }

    public function test_correct_customer_login_issues_jwt_with_permissions(): void
    {
        $id = $this->seed('user@example.com', 'correct-horse-battery', permissions: ['invoices:read', 'invoices:pay']);

        $response = $this->login(['email' => 'user@example.com', 'password' => 'correct-horse-battery']);

        self::assertSame(200, $response->getStatusCode());
        $body = $this->jsonBody($response);
        self::assertSame($id, $body['userId']);
        self::assertFalse($body['isAdmin']);
        self::assertSame(7, $body['customerId']);
        self::assertSame(['invoices:read', 'invoices:pay'], $body['permissions']);

        $claims = $this->jwt->verify($body['token']);
        self::assertSame($id, $claims['uid']);
        self::assertSame(['invoices:read', 'invoices:pay'], $claims['permissions']);
    }

    public function test_admin_login_reports_is_admin_and_empty_permissions(): void
    {
        $this->seed('admin@example.com', 'correct-horse-battery', isAdmin: true, customerId: null, permissions: []);

        $response = $this->login(['email' => 'admin@example.com', 'password' => 'correct-horse-battery']);

        self::assertSame(200, $response->getStatusCode());
        $body = $this->jsonBody($response);
        self::assertTrue($body['isAdmin']);
        self::assertNull($body['customerId']);
    }

    public function test_login_reports_must_change_password_flag(): void
    {
        $id = $this->seed('admin@example.com', 'temp-setup-pass', isAdmin: true, customerId: null, permissions: []);
        $this->users->update($id, ['must_change_password' => true]);

        $response = $this->login(['email' => 'admin@example.com', 'password' => 'temp-setup-pass']);

        self::assertSame(200, $response->getStatusCode());
        self::assertTrue($this->jsonBody($response)['mustChangePassword']);
    }

    public function test_email_lookup_is_case_insensitive(): void
    {
        $this->seed('user@example.com', 'correct-horse-battery');

        self::assertSame(200, $this->login(['email' => 'USER@example.com', 'password' => 'correct-horse-battery'])->getStatusCode());
    }

    public function test_rate_limited_returns_429_before_lookup(): void
    {
        $this->seed('user@example.com', 'correct-horse-battery');
        $this->rateLimiter = new FakeRateLimiter(allowed: false, remaining: 0);

        $response = $this->login(['email' => 'user@example.com', 'password' => 'correct-horse-battery']);

        self::assertSame(429, $response->getStatusCode());
        self::assertSame([], $this->sessions->sessions);
    }

    /** @param array<string,mixed> $payload */
    private function login(array $payload): ResponseInterface
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('POST', '/login')
            ->withParsedBody($payload);
        $action = new LoginAction($this->users, $this->jwt, $this->sessions, $this->cookies, $this->rateLimiter, $this->remember, $this->rememberCookies);
        return $action($request, new Response());
    }

    /** @return array<string,mixed> */
    private function jsonBody(ResponseInterface $response): array
    {
        $response->getBody()->rewind();
        return json_decode($response->getBody()->getContents(), true);
    }
}
