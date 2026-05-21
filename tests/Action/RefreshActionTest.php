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
use Tds\AuthApi\Tests\Support\FakeSessionRepository;
use Tds\AuthApi\Tests\Support\Keys;

final class RefreshActionTest extends TestCase
{
    private JwtService $jwt;
    private FakeSessionRepository $sessions;
    private CookieFactory $cookies;

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

    public function test_cookie_fallback_used_when_no_authorization_header(): void
    {
        $issued = $this->jwt->issueAdmin();
        $this->sessions->record($issued['jti'], null, true, $issued['expiresAt']);

        $request = (new ServerRequestFactory())
            ->createServerRequest('POST', '/refresh')
            ->withCookieParams(['tds_session' => $issued['token']]);
        $response = (new RefreshAction($this->jwt, $this->sessions, $this->cookies))($request, new Response());

        self::assertSame(200, $response->getStatusCode());
    }

    private function refresh(?string $bearer = null): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('POST', '/refresh');
        if ($bearer !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $bearer);
        }
        return (new RefreshAction($this->jwt, $this->sessions, $this->cookies))($request, new Response());
    }

    /** @return array<string,mixed> */
    private function jsonBody(ResponseInterface $response): array
    {
        $response->getBody()->rewind();
        return json_decode($response->getBody()->getContents(), true);
    }
}
