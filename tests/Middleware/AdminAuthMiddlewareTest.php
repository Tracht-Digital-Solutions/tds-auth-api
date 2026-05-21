<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Middleware;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\AdminAuthMiddleware;

final class AdminAuthMiddlewareTest extends TestCase
{
    public function test_missing_header_returns_401(): void
    {
        $response = $this->run(new AdminAuthMiddleware('expected-token'), bearer: null);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(['error' => 'unauthorized'], $this->jsonBody($response));
    }

    public function test_wrong_token_returns_401(): void
    {
        $response = $this->run(new AdminAuthMiddleware('expected-token'), bearer: 'wrong');

        self::assertSame(401, $response->getStatusCode());
    }

    public function test_unconfigured_token_returns_401_with_explanation(): void
    {
        $response = $this->run(new AdminAuthMiddleware(''), bearer: 'whatever');

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(
            ['error' => 'admin token not configured'],
            $this->jsonBody($response),
        );
    }

    public function test_correct_token_calls_next_handler(): void
    {
        $called = false;
        $handler = new class($called) implements RequestHandlerInterface {
            public function __construct(private bool &$called) {}
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->called = true;
                return (new Response())->withStatus(200);
            }
        };
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', '/whatever')
            ->withHeader('Authorization', 'Bearer expected-token');

        $response = (new AdminAuthMiddleware('expected-token'))->process($request, $handler);

        self::assertTrue($called);
        self::assertSame(200, $response->getStatusCode());
    }

    public function test_malformed_authorization_header_returns_401(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', '/whatever')
            ->withHeader('Authorization', 'Basic dXNlcjpwYXNz');
        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $r): ResponseInterface
            {
                throw new \RuntimeException('handler must not run on auth fail');
            }
        };

        $response = (new AdminAuthMiddleware('expected-token'))->process($request, $handler);

        self::assertSame(401, $response->getStatusCode());
    }

    private function run(AdminAuthMiddleware $mw, ?string $bearer): ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('GET', '/whatever');
        if ($bearer !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $bearer);
        }
        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $r): ResponseInterface
            {
                return (new Response())->withStatus(200);
            }
        };
        return $mw->process($request, $handler);
    }

    /** @return array<string,mixed> */
    private function jsonBody(ResponseInterface $response): array
    {
        $response->getBody()->rewind();
        return json_decode($response->getBody()->getContents(), true);
    }
}
