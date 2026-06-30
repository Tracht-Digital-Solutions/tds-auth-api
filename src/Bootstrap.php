<?php
declare(strict_types=1);

namespace Tds\AuthApi;

use DI\Container;
use Dotenv\Dotenv;
use PDO;
use Slim\App;
use Slim\Factory\AppFactory;
use Tds\AuthApi\Action\Admin\CreateCustomerCredentialAction;
use Tds\AuthApi\Action\Admin\ListSessionsAction;
use Tds\AuthApi\Action\Admin\LoginAction as AdminLoginAction;
use Tds\AuthApi\Action\Admin\LogoutAction as AdminLogoutAction;
use Tds\AuthApi\Action\Admin\RevokeSessionAction;
use Tds\AuthApi\Action\Customer\ChangePasswordAction as CustomerChangePasswordAction;
use Tds\AuthApi\Action\Customer\LoginAction as CustomerLoginAction;
use Tds\AuthApi\Action\HealthAction;
use Tds\AuthApi\Action\JwksAction;
use Tds\AuthApi\Action\RefreshAction;
use Tds\AuthApi\Infrastructure\Database;
use Tds\AuthApi\Infrastructure\PdoSessionRepository;
use Tds\AuthApi\Middleware\AdminAuthMiddleware;
use Tds\AuthApi\Middleware\CorsMiddleware;
use Tds\AuthApi\Middleware\CustomerAuthMiddleware;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Service\PdoRateLimiter;
use Tds\AuthApi\Service\RateLimiter;
use Tds\AuthApi\Service\SessionRepository;

final class Bootstrap
{
    public static function createApp(string $rootDir): App
    {
        if (file_exists($rootDir . '/.env')) {
            Dotenv::createImmutable($rootDir)->load();
        }

        $container = new Container();

        $container->set(PDO::class, fn () => Database::connect([
            'host' => self::env('DB_HOST'),
            'port' => self::env('DB_PORT', '3306'),
            'name' => self::env('DB_NAME'),
            'user' => self::env('DB_USER'),
            'pass' => self::env('DB_PASS'),
        ]));

        // Health probe resolves PDO + JwtService lazily (inside its own
        // try/catch) so a DB outage or missing/corrupt key reports
        // down/missing with HTTP 200 instead of 5xx'ing during construction.
        $container->set(HealthAction::class, fn (Container $c) => new HealthAction(
            static fn (): PDO => $c->get(PDO::class),
            static fn (): JwtService => $c->get(JwtService::class),
        ));

        $container->set(SessionRepository::class, fn (Container $c) => new PdoSessionRepository($c->get(PDO::class)));

        $container->set(CustomerAuthMiddleware::class, fn (Container $c) => new CustomerAuthMiddleware(
            $c->get(JwtService::class),
            $c->get(SessionRepository::class),
            $c->get(CookieFactory::class),
        ));

        $container->set(RateLimiter::class, fn (Container $c) => new PdoRateLimiter(
            pdo: $c->get(PDO::class),
            limit: (int) self::env('LOGIN_RATE_LIMIT', '10'),
            windowSeconds: (int) self::env('LOGIN_RATE_WINDOW_SECONDS', '900'),
        ));

        $container->set(JwtService::class, fn () => new JwtService(
            privateKeyPem: self::loadPrivateKey($rootDir),
            publicKeyPem: self::loadPublicKey($rootDir),
            keyId: self::env('JWT_KEY_ID', 'tds-auth-2026-1'),
            issuer: self::env('JWT_ISSUER', 'https://api.tracht-digital.de/auth'),
            ttlSeconds: (int) self::env('JWT_TTL_SECONDS', '3600'),
            refreshTtlSeconds: (int) self::env('JWT_REFRESH_TTL_SECONDS', (string) (60 * 60 * 24 * 30)),
        ));

        $container->set(CookieFactory::class, fn () => new CookieFactory(
            name: self::env('COOKIE_NAME', 'tds_session'),
            domain: self::env('COOKIE_DOMAIN', '.tracht-digital.de'),
            secure: self::env('APP_ENV') === 'production',
        ));

        AppFactory::setContainer($container);
        $app = AppFactory::create();
        $app->addBodyParsingMiddleware();
        $app->add(new CorsMiddleware(self::corsOrigins()));
        $app->addRoutingMiddleware();
        $app->addErrorMiddleware(self::env('APP_ENV') !== 'production', true, true);

        $admin = new AdminAuthMiddleware(self::env('ADMIN_TOKEN', ''));

        $app->get('/healthz', HealthAction::class);
        $app->post('/admin/login', AdminLoginAction::class);
        $app->delete('/admin/login', AdminLogoutAction::class);
        $app->post('/admin/customer-credentials', CreateCustomerCredentialAction::class)->add($admin);
        $app->get('/admin/sessions', ListSessionsAction::class)->add($admin);
        $app->delete('/admin/sessions/{jti}', RevokeSessionAction::class)->add($admin);
        $app->post('/customer/login', CustomerLoginAction::class);
        $app->put('/customer/password', CustomerChangePasswordAction::class)->add(CustomerAuthMiddleware::class);
        $app->post('/refresh', RefreshAction::class);
        $app->get('/.well-known/jwks.json', JwksAction::class);

        return $app;
    }

    /**
     * Env reader. NB: explicit `?? false` checks — never
     * `$_ENV[$key] ?? getenv($key) ?: $default`, which clobbers falsy
     * values ("0", "") because `??` binds tighter than `?:` (the bug
     * that bit all four APIs via copy-paste).
     */
    private static function env(string $key, ?string $default = null): string
    {
        $v = $_ENV[$key] ?? false;
        if ($v === false) {
            $v = getenv($key);
        }
        if ($v === false) {
            $v = $default;
        }
        if ($v === null) {
            throw new \RuntimeException("Missing required env var: {$key}");
        }
        return (string) $v;
    }

    /** @return string[] */
    private static function corsOrigins(): array
    {
        // Use the safe env() helper — NOT the `?? getenv() ?: ''` one-liner the
        // comment above warns against (the `??`-binds-tighter-than-`?:` trap).
        $raw = self::env('CORS_ALLOWED_ORIGINS', '');
        return array_values(array_filter(array_map('trim', explode(',', $raw))));
    }

    private static function loadPrivateKey(string $rootDir): string
    {
        $env = self::env('JWT_PRIVATE_KEY', '');
        if ($env !== '') {
            return str_replace('\n', "\n", $env);
        }
        $file = $rootDir . '/keys/private.pem';
        if (!file_exists($file)) {
            throw new \RuntimeException('JWT_PRIVATE_KEY not set and keys/private.pem not present');
        }
        return (string) file_get_contents($file);
    }

    private static function loadPublicKey(string $rootDir): string
    {
        $file = $rootDir . '/keys/public.pem';
        if (!file_exists($file)) {
            throw new \RuntimeException('keys/public.pem missing — run `composer keygen`');
        }
        return (string) file_get_contents($file);
    }
}
