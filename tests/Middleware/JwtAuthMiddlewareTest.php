<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Middleware;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Tds\AuthApi\Domain\AppUser;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Tests\Support\FakeSessionRepository;
use Tds\AuthApi\Tests\Support\Keys;
use Tds\AuthApi\Tests\Support\StubHandler;

final class JwtAuthMiddlewareTest extends TestCase
{
    private JwtService $jwt;
    private FakeSessionRepository $sessions;

    protected function setUp(): void
    {
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
    }

    public function test_missing_token_returns_401(): void
    {
        $handler = new StubHandler();
        $response = $this->middleware()->process($this->request(), $handler);

        self::assertSame(401, $response->getStatusCode());
        self::assertFalse($handler->reached);
    }

    public function test_garbage_token_returns_401(): void
    {
        $handler = new StubHandler();
        $response = $this->middleware()->process($this->request('not-a-jwt'), $handler);

        self::assertSame(401, $response->getStatusCode());
    }

    public function test_revoked_session_returns_401(): void
    {
        $issued = $this->jwt->issueForUser($this->user(true));
        $this->sessions->record($issued['jti'], null, true, $issued['expiresAt'], 1);
        $this->sessions->revoke($issued['jti']);

        $response = $this->middleware()->process($this->request($issued['token']), new StubHandler());

        self::assertSame(401, $response->getStatusCode());
    }

    public function test_session_middleware_passes_any_valid_user(): void
    {
        $issued = $this->jwt->issueForUser($this->user(false));
        $this->sessions->record($issued['jti'], 7, false, $issued['expiresAt'], 2);

        $handler = new StubHandler();
        $response = $this->middleware(requireAdmin: false)->process($this->request($issued['token']), $handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertTrue($handler->reached);
    }

    public function test_admin_gate_rejects_non_admin_with_403(): void
    {
        $issued = $this->jwt->issueForUser($this->user(false));
        $this->sessions->record($issued['jti'], 7, false, $issued['expiresAt'], 2);

        $handler = new StubHandler();
        $response = $this->middleware(requireAdmin: true)->process($this->request($issued['token']), $handler);

        self::assertSame(403, $response->getStatusCode());
        self::assertFalse($handler->reached);
    }

    public function test_admin_gate_accepts_admin(): void
    {
        $issued = $this->jwt->issueForUser($this->user(true));
        $this->sessions->record($issued['jti'], null, true, $issued['expiresAt'], 1);

        $handler = new StubHandler();
        $response = $this->middleware(requireAdmin: true)->process($this->request($issued['token']), $handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertTrue($handler->reached);
    }

    public function test_cookie_token_is_accepted(): void
    {
        $issued = $this->jwt->issueForUser($this->user(false));
        $this->sessions->record($issued['jti'], 7, false, $issued['expiresAt'], 2);

        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', '/me')
            ->withCookieParams(['tds_session' => $issued['token']]);

        $response = $this->middleware()->process($request, new StubHandler());

        self::assertSame(200, $response->getStatusCode());
    }

    private function user(bool $admin): AppUser
    {
        return new AppUser(
            id: $admin ? 1 : 2,
            email: $admin ? 'admin@example.com' : 'cust@example.com',
            name: null,
            isAdmin: $admin,
            customerId: $admin ? null : 7,
            permissions: $admin ? [] : ['invoices:read'],
            status: 'active',
            passwordHash: 'x',
        );
    }

    private function middleware(bool $requireAdmin = false): JwtAuthMiddleware
    {
        return new JwtAuthMiddleware($this->jwt, $this->sessions, $requireAdmin);
    }

    private function request(?string $bearer = null): \Psr\Http\Message\ServerRequestInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('GET', '/me');
        if ($bearer !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $bearer);
        }
        return $request;
    }
}
