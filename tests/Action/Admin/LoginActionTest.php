<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action\Admin;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\Admin\LoginAction;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Tests\Support\FakeSessionRepository;
use Tds\AuthApi\Tests\Support\Keys;

final class LoginActionTest extends TestCase
{
    private JwtService $jwt;
    private FakeSessionRepository $sessions;
    private CookieFactory $cookies;
    private ?string $originalAdminToken;

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
        $this->cookies = new CookieFactory('tds_session', '.tracht-digital.de', secure: false);

        $this->originalAdminToken = getenv('ADMIN_TOKEN') === false ? null : (string) getenv('ADMIN_TOKEN');
        putenv('ADMIN_TOKEN=correct-horse-battery-staple');
    }

    protected function tearDown(): void
    {
        if ($this->originalAdminToken === null) {
            putenv('ADMIN_TOKEN');
        } else {
            putenv('ADMIN_TOKEN=' . $this->originalAdminToken);
        }
    }

    public function test_missing_env_returns_500(): void
    {
        putenv('ADMIN_TOKEN');

        $response = $this->post(['token' => 'anything']);

        self::assertSame(500, $response->getStatusCode());
        self::assertSame(['error' => 'ADMIN_TOKEN not configured'], $this->jsonBody($response));
    }

    public function test_missing_token_returns_401(): void
    {
        $response = $this->post([]);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(['error' => 'Unauthorized'], $this->jsonBody($response));
    }

    public function test_wrong_token_returns_401(): void
    {
        $response = $this->post(['token' => 'nope']);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame([], $this->sessions->sessions, 'session must not be recorded on failed login');
    }

    public function test_non_array_body_returns_401(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('POST', '/admin/login');
        $response = $this->action()($request, new Response());

        self::assertSame(401, $response->getStatusCode());
    }

    public function test_correct_token_issues_jwt_records_session_and_sets_cookie(): void
    {
        $response = $this->post(['token' => 'correct-horse-battery-staple']);

        self::assertSame(200, $response->getStatusCode());
        $body = $this->jsonBody($response);
        self::assertNotEmpty($body['token']);
        self::assertIsInt($body['expiresAt']);

        $claims = $this->jwt->verify($body['token']);
        self::assertTrue($claims['admin']);
        self::assertArrayHasKey($claims['jti'], $this->sessions->sessions);
        self::assertTrue($this->sessions->sessions[$claims['jti']]['admin']);
        self::assertNull($this->sessions->sessions[$claims['jti']]['customer_id']);

        $cookie = $response->getHeaderLine('Set-Cookie');
        self::assertStringContainsString('tds_session=', $cookie);
        self::assertStringContainsString('Max-Age=900', $cookie);
    }

    /** @param array<string,mixed> $payload */
    private function post(array $payload): ResponseInterface
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('POST', '/admin/login')
            ->withParsedBody($payload);
        return $this->action()($request, new Response());
    }

    private function action(): LoginAction
    {
        return new LoginAction($this->jwt, $this->sessions, $this->cookies);
    }

    /** @return array<string,mixed> */
    private function jsonBody(ResponseInterface $response): array
    {
        $response->getBody()->rewind();
        return json_decode($response->getBody()->getContents(), true);
    }
}
