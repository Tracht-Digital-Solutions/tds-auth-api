<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Middleware;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\CustomerAuthMiddleware;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Tests\Support\FakeSessionRepository;
use Tds\AuthApi\Tests\Support\Keys;

final class CustomerAuthMiddlewareTest extends TestCase
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

    public function test_missing_token_returns_401(): void
    {
        $response = $this->dispatch(token: null);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(['error' => 'No token presented'], $this->jsonBody($response));
    }

    public function test_garbage_token_returns_401(): void
    {
        $response = $this->dispatch(token: 'not-a-jwt');

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(['error' => 'Invalid token'], $this->jsonBody($response));
    }

    public function test_admin_token_returns_403(): void
    {
        $issued = $this->jwt->issueAdmin();
        $this->sessions->record($issued['jti'], null, true, $issued['expiresAt']);

        $response = $this->dispatch(token: $issued['token']);

        self::assertSame(403, $response->getStatusCode());
        self::assertSame(['error' => 'Customer session required'], $this->jsonBody($response));
    }

    public function test_revoked_session_returns_401(): void
    {
        $issued = $this->jwt->issueCustomer(7);
        $this->sessions->record($issued['jti'], 7, false, $issued['expiresAt']);
        $this->sessions->revoke($issued['jti']);

        $response = $this->dispatch(token: $issued['token']);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(['error' => 'Session revoked'], $this->jsonBody($response));
    }

    public function test_valid_customer_passes_through_with_attributes(): void
    {
        $issued = $this->jwt->issueCustomer(7);
        $this->sessions->record($issued['jti'], 7, false, $issued['expiresAt']);

        $seen = [];
        $handler = new class($seen) implements RequestHandlerInterface {
            /** @param array<string,mixed> $seen */
            public function __construct(private array &$seen) {}
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->seen = [
                    'customer_id' => $request->getAttribute(CustomerAuthMiddleware::ATTR_CUSTOMER_ID),
                    'jti' => $request->getAttribute(CustomerAuthMiddleware::ATTR_JTI),
                ];
                return (new Response())->withStatus(204);
            }
        };

        $request = (new ServerRequestFactory())
            ->createServerRequest('PUT', '/customer/password')
            ->withHeader('Authorization', 'Bearer ' . $issued['token']);

        $response = $this->middleware()->process($request, $handler);

        self::assertSame(204, $response->getStatusCode());
        self::assertSame(7, $seen['customer_id']);
        self::assertSame($issued['jti'], $seen['jti']);
    }

    public function test_token_via_cookie_is_accepted(): void
    {
        $issued = $this->jwt->issueCustomer(7);
        $this->sessions->record($issued['jti'], 7, false, $issued['expiresAt']);

        $request = (new ServerRequestFactory())
            ->createServerRequest('PUT', '/customer/password')
            ->withCookieParams(['tds_session' => $issued['token']]);

        $response = $this->middleware()->process($request, $this->okHandler());

        self::assertSame(200, $response->getStatusCode());
    }

    private function middleware(): CustomerAuthMiddleware
    {
        return new CustomerAuthMiddleware($this->jwt, $this->sessions, $this->cookies);
    }

    private function dispatch(?string $token): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('PUT', '/customer/password');
        if ($token !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $token);
        }
        return $this->middleware()->process($request, $this->okHandler());
    }

    private function okHandler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return (new Response())->withStatus(200);
            }
        };
    }

    /** @return array<string,mixed> */
    private function jsonBody(ResponseInterface $response): array
    {
        $response->getBody()->rewind();
        return json_decode($response->getBody()->getContents(), true);
    }
}
