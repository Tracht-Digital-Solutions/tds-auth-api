<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Middleware;

use PHPUnit\Framework\TestCase;
use Slim\Psr7\Factory\ServerRequestFactory;
use Tds\AuthApi\Middleware\CorsMiddleware;
use Tds\AuthApi\Tests\Support\StubHandler;

final class CorsMiddlewareTest extends TestCase
{
    private const ALLOWED = ['https://management.tracht-digital.de'];

    private function request(string $method, ?string $origin): \Psr\Http\Message\ServerRequestInterface
    {
        $r = (new ServerRequestFactory())->createServerRequest($method, '/admin/login');
        return $origin === null ? $r : $r->withHeader('Origin', $origin);
    }

    public function test_preflight_returns_204_without_reaching_handler(): void
    {
        $handler = new StubHandler();
        $res = (new CorsMiddleware(self::ALLOWED))->process($this->request('OPTIONS', self::ALLOWED[0]), $handler);

        self::assertSame(204, $res->getStatusCode());
        self::assertFalse($handler->reached);
    }

    public function test_allowed_origin_gets_credentials_true(): void
    {
        // auth-api issues cookies, so credentialed CORS is required — the
        // Allow-Credentials header must accompany the echoed origin.
        $res = (new CorsMiddleware(self::ALLOWED))->process($this->request('POST', self::ALLOWED[0]), new StubHandler());

        self::assertSame(self::ALLOWED[0], $res->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame('true', $res->getHeaderLine('Access-Control-Allow-Credentials'));
        self::assertSame('Origin', $res->getHeaderLine('Vary'));
    }

    public function test_disallowed_origin_never_gets_credentials_or_origin(): void
    {
        // Credentials must NEVER be granted to an un-allowlisted origin.
        $res = (new CorsMiddleware(self::ALLOWED))->process($this->request('POST', 'https://evil.example'), new StubHandler());

        self::assertSame('', $res->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame('', $res->getHeaderLine('Access-Control-Allow-Credentials'));
    }

    public function test_static_cors_headers_always_present(): void
    {
        $res = (new CorsMiddleware(self::ALLOWED))->process($this->request('POST', null), new StubHandler());

        self::assertStringContainsString('DELETE', $res->getHeaderLine('Access-Control-Allow-Methods'));
        self::assertStringContainsString('Authorization', $res->getHeaderLine('Access-Control-Allow-Headers'));
        self::assertSame('600', $res->getHeaderLine('Access-Control-Max-Age'));
    }
}
