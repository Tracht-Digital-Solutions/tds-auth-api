<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\RefreshAction;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Service\RememberCookieFactory;
use Tds\AuthApi\Service\RememberTokenService;
use Tds\AuthApi\Tests\Support\FakeAppUserRepository;
use Tds\AuthApi\Tests\Support\FakeRememberTokenRepository;
use Tds\AuthApi\Tests\Support\FakeSessionRepository;
use Tds\AuthApi\Tests\Support\Keys;

final class RefreshActionTest extends TestCase
{
    private JwtService $jwt;
    private FakeSessionRepository $sessions;
    private CookieFactory $cookies;
    private FakeAppUserRepository $users;
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
        $this->users = new FakeAppUserRepository();
        $this->rememberRepo = new FakeRememberTokenRepository();
        $this->remember = new RememberTokenService($this->rememberRepo, 2592000);
        $this->rememberCookies = new RememberCookieFactory(new CookieFactory('tds_remember', '.local', secure: false));
    }

    public function test_no_token_returns_401(): void
    {
        $response = $this->refresh();

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(['error' => 'No token presented'], $this->jsonBody($response));
    }

    public function test_invalid_token_returns_401(): void
    {
        $response = $this->refresh(bearer: 'a.b.c');

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(['error' => 'Invalid token'], $this->jsonBody($response));
    }

    public function test_revoked_session_returns_401(): void
    {
        $issued = $this->jwt->issueAdmin();
        $this->sessions->record($issued['jti'], null, true, $issued['expiresAt']);
        $this->sessions->revoke($issued['jti']);

        $response = $this->refresh(bearer: $issued['token']);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(['error' => 'Session revoked'], $this->jsonBody($response));
    }

    public function test_unknown_jti_treated_as_revoked(): void
    {
        $this->sessions->defaultRevokedForUnknown = true;
        $issued = $this->jwt->issueAdmin();

        $response = $this->refresh(bearer: $issued['token']);

        self::assertSame(401, $response->getStatusCode());
    }

    public function test_admin_token_refresh_issues_new_admin_jwt(): void
    {
        $issued = $this->jwt->issueAdmin();
        $this->sessions->record($issued['jti'], null, true, $issued['expiresAt']);

        $response = $this->refresh(bearer: $issued['token']);

        self::assertSame(200, $response->getStatusCode());
        $body = $this->jsonBody($response);
        $claims = $this->jwt->verify($body['token']);
        self::assertTrue($claims['admin']);
        self::assertNotSame($issued['jti'], $claims['jti'], 'refresh must rotate jti');
    }

    public function test_customer_token_refresh_preserves_customer_id(): void
    {
        $issued = $this->jwt->issueCustomer(7);
        $this->sessions->record($issued['jti'], 7, false, $issued['expiresAt']);

        $response = $this->refresh(bearer: $issued['token']);

        self::assertSame(200, $response->getStatusCode());
        $body = $this->jsonBody($response);
        $claims = $this->jwt->verify($body['token']);
        self::assertFalse($claims['admin']);
        self::assertSame(7, $claims['customer_id']);
    }

    public function test_a_non_admin_without_a_company_can_refresh(): void
    {
        // This used to `throw new \RuntimeException('non-admin without
        // customer_id')`, i.e. a 500. LoginAction never checked, so such an
        // account signed in fine and then broke an hour later on its first
        // refresh — and it broke in the worst possible shape: the panel's
        // backstop saw a 500 while /me still answered 200, so the session
        // neither recovered nor ended. Company membership is optional by
        // design (a user may belong to none, one, or several).
        $issued = $this->jwt->issuePrincipal(false, null, 12, [], companies: []);
        $this->sessions->record($issued['jti'], null, false, $issued['expiresAt'], 12);

        $response = $this->refresh(bearer: $issued['token']);

        self::assertSame(200, $response->getStatusCode());
        $claims = $this->jwt->verify($this->jsonBody($response)['token']);
        self::assertFalse($claims['admin']);
        self::assertNull($claims['customer_id']);
        self::assertSame(12, $claims['uid']);
        self::assertSame([], (array) $claims['companies']);
    }

    public function test_carries_the_identity_claims_forward(): void
    {
        // `email` / `name` are what tds-core-frontend-api's JwtUserContext
        // reads; dropping them on refresh would blank the panel's profile
        // menu an hour into every session.
        $issued = $this->jwt->issuePrincipal(
            false,
            7,
            12,
            ['tickets:read'],
            email: 'user@example.com',
            name: 'Julian',
        );
        $this->sessions->record($issued['jti'], 7, false, $issued['expiresAt'], 12);

        $response = $this->refresh(bearer: $issued['token']);

        $claims = $this->jwt->verify($this->jsonBody($response)['token']);
        self::assertSame('user@example.com', $claims['email']);
        self::assertSame('Julian', $claims['name']);
    }

    public function test_cookie_fallback_used_when_no_authorization_header(): void
    {
        $issued = $this->jwt->issueAdmin();
        $this->sessions->record($issued['jti'], null, true, $issued['expiresAt']);

        $request = (new ServerRequestFactory())
            ->createServerRequest('POST', '/refresh')
            ->withCookieParams(['tds_session' => $issued['token']]);
        $response = (new RefreshAction($this->jwt, $this->sessions, $this->cookies, $this->users, $this->remember, $this->rememberCookies))($request, new Response());

        self::assertSame(200, $response->getStatusCode());
    }

    private function refresh(?string $bearer = null): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('POST', '/refresh');
        if ($bearer !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $bearer);
        }
        return (new RefreshAction($this->jwt, $this->sessions, $this->cookies, $this->users, $this->remember, $this->rememberCookies))($request, new Response());
    }

    /** @return array<string,mixed> */
    private function jsonBody(ResponseInterface $response): array
    {
        $response->getBody()->rewind();
        return json_decode($response->getBody()->getContents(), true);
    }
}
