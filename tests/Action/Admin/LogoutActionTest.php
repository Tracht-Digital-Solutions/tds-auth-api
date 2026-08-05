<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action\Admin;

use PHPUnit\Framework\TestCase;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\Admin\LogoutAction;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Service\RememberCookieFactory;
use Tds\AuthApi\Service\RememberTokenService;
use Tds\AuthApi\Tests\Support\FakeRememberTokenRepository;
use Tds\AuthApi\Tests\Support\FakeSessionRepository;
use Tds\AuthApi\Tests\Support\Keys;

final class LogoutActionTest extends TestCase
{
    private JwtService $jwt;
    private FakeSessionRepository $sessions;
    private CookieFactory $cookies;
    private FakeRememberTokenRepository $rememberRepo;
    private RememberTokenService $remember;
    private RememberCookieFactory $rememberCookies;

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
        $this->cookies = new CookieFactory('tds_session', '.local', secure: false);
        $this->rememberRepo = new FakeRememberTokenRepository();
        $this->remember = new RememberTokenService($this->rememberRepo, 2592000);
        $this->rememberCookies = new RememberCookieFactory(new CookieFactory('tds_remember', '.local', secure: false));
    }

    public function test_no_token_returns_204_and_clears_cookie(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest('DELETE', '/admin/login');
        $response = (new LogoutAction($this->jwt, $this->sessions, $this->cookies, $this->remember, $this->rememberCookies))($request, new Response());

        self::assertSame(204, $response->getStatusCode());
        self::assertStringContainsString('Max-Age=0', $response->getHeaderLine('Set-Cookie'));
        self::assertSame([], $this->sessions->revoked);
    }

    public function test_invalid_token_still_returns_204(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('DELETE', '/admin/login')
            ->withHeader('Authorization', 'Bearer garbage.token.value');
        $response = (new LogoutAction($this->jwt, $this->sessions, $this->cookies, $this->remember, $this->rememberCookies))($request, new Response());

        self::assertSame(204, $response->getStatusCode());
        self::assertSame([], $this->sessions->revoked, 'invalid token cannot reveal a jti to revoke');
    }

    public function test_valid_token_revokes_session(): void
    {
        $issued = $this->jwt->issueAdmin();
        $this->sessions->record($issued['jti'], null, true, $issued['expiresAt']);

        $request = (new ServerRequestFactory())
            ->createServerRequest('DELETE', '/admin/login')
            ->withHeader('Authorization', 'Bearer ' . $issued['token']);
        $response = (new LogoutAction($this->jwt, $this->sessions, $this->cookies, $this->remember, $this->rememberCookies))($request, new Response());

        self::assertSame(204, $response->getStatusCode());
        self::assertSame([$issued['jti']], $this->sessions->revoked);
    }

    public function test_token_read_from_cookie_when_no_bearer(): void
    {
        $issued = $this->jwt->issueAdmin();
        $this->sessions->record($issued['jti'], null, true, $issued['expiresAt']);

        $request = (new ServerRequestFactory())
            ->createServerRequest('DELETE', '/admin/login')
            ->withCookieParams(['tds_session' => $issued['token']]);
        $response = (new LogoutAction($this->jwt, $this->sessions, $this->cookies, $this->remember, $this->rememberCookies))($request, new Response());

        self::assertSame(204, $response->getStatusCode());
        self::assertSame([$issued['jti']], $this->sessions->revoked);
    }
}
