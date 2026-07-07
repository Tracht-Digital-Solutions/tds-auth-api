<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests;

use PHPUnit\Framework\TestCase;
use Slim\Psr7\Factory\ServerRequestFactory;
use Tds\AuthApi\Bootstrap;
use Tds\AuthApi\Tests\Support\Keys;

/**
 * Regression test for the CORS preflight through the REAL app (not the
 * middleware in isolation): Slim middleware is LIFO, so when CorsMiddleware
 * was added before addRoutingMiddleware() the routing middleware ran first
 * and 405'd every OPTIONS request (no OPTIONS routes are registered) before
 * CORS could short-circuit it — browsers then blocked every cross-origin
 * JSON/Authorization request, including the panel logins.
 */
final class PreflightTest extends TestCase
{
    private const ORIGIN = 'https://management.tracht-digital.de';

    private string $rootDir;

    protected function setUp(): void
    {
        // createApp() eagerly connects PDO (the session repository feeds the
        // auth middlewares), so this needs the test DB like the other
        // DB-backed integration tests.
        $dsn = getenv('TDS_TEST_DB_DSN') ?: '';
        if ($dsn === '') {
            self::markTestSkipped('Set TDS_TEST_DB_DSN to run the preflight integration test.');
        }
        preg_match('/host=([^;]+)/', $dsn, $host);
        preg_match('/port=([^;]+)/', $dsn, $port);
        preg_match('/dbname=([^;]+)/', $dsn, $name);
        $_ENV['DB_HOST'] = $host[1] ?? '127.0.0.1';
        $_ENV['DB_PORT'] = $port[1] ?? '3306';
        $_ENV['DB_NAME'] = $name[1] ?? '';
        $_ENV['DB_USER'] = getenv('TDS_TEST_DB_USER') ?: 'root';
        $_ENV['DB_PASS'] = getenv('TDS_TEST_DB_PASS') ?: '';

        // createApp() also eagerly builds JwtService (for the auth middlewares),
        // so give it a throwaway root with a real keypair — CI has no keys/ files.
        $this->rootDir = sys_get_temp_dir() . '/tds-auth-preflight-' . bin2hex(random_bytes(4));
        mkdir($this->rootDir . '/keys', 0777, true);
        $keys = new Keys();
        file_put_contents($this->rootDir . '/keys/private.pem', $keys->privatePem);
        file_put_contents($this->rootDir . '/keys/public.pem', $keys->publicPem);

        $_ENV['APP_ENV'] = 'test';
        $_ENV['CORS_ALLOWED_ORIGINS'] = self::ORIGIN;
    }

    protected function tearDown(): void
    {
        @unlink($this->rootDir . '/keys/private.pem');
        @unlink($this->rootDir . '/keys/public.pem');
        @rmdir($this->rootDir . '/keys');
        @rmdir($this->rootDir);
        unset(
            $_ENV['APP_ENV'],
            $_ENV['CORS_ALLOWED_ORIGINS'],
            $_ENV['DB_HOST'],
            $_ENV['DB_PORT'],
            $_ENV['DB_NAME'],
            $_ENV['DB_USER'],
            $_ENV['DB_PASS'],
        );
    }

    public function test_options_login_preflight_returns_204_with_cors_headers(): void
    {
        $app = Bootstrap::createApp($this->rootDir);

        $request = (new ServerRequestFactory())
            ->createServerRequest('OPTIONS', '/login')
            ->withHeader('Origin', self::ORIGIN)
            ->withHeader('Access-Control-Request-Method', 'POST')
            ->withHeader('Access-Control-Request-Headers', 'content-type');

        $response = $app->handle($request);

        self::assertSame(204, $response->getStatusCode());
        self::assertSame(self::ORIGIN, $response->getHeaderLine('Access-Control-Allow-Origin'));
        self::assertSame('true', $response->getHeaderLine('Access-Control-Allow-Credentials'));
        self::assertStringContainsString('POST', $response->getHeaderLine('Access-Control-Allow-Methods'));
    }
}
