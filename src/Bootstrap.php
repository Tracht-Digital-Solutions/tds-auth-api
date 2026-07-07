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
use Tds\AuthApi\Action\Admin\LogoutAction as AdminLogoutAction;
use Tds\AuthApi\Action\Admin\RevokeSessionAction;
use Tds\AuthApi\Action\Admin\Users\CreateUserAction;
use Tds\AuthApi\Action\Admin\Users\DeleteUserAction;
use Tds\AuthApi\Action\Admin\Users\ListUsersAction;
use Tds\AuthApi\Action\Admin\Users\ResetPasswordAction;
use Tds\AuthApi\Action\Admin\Users\UpdateUserAction;
use Tds\AuthApi\Action\ChangePasswordAction;
use Tds\AuthApi\Action\HealthAction;
use Tds\AuthApi\Action\JwksAction;
use Tds\AuthApi\Action\LoginAction;
use Tds\AuthApi\Action\MeAction;
use Tds\AuthApi\Action\RefreshAction;
use Tds\AuthApi\Infrastructure\Database;
use Tds\AuthApi\Infrastructure\PdoAppUserRepository;
use Tds\AuthApi\Infrastructure\PdoSessionRepository;
use Tds\AuthApi\Middleware\AdminAuthMiddleware;
use Tds\AuthApi\Middleware\CorsMiddleware;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\AppUserRepository;
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

        $container->set(AppUserRepository::class, fn (Container $c) => new PdoAppUserRepository($c->get(PDO::class)));

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
        $app->addRoutingMiddleware();
        $app->addErrorMiddleware(self::env('APP_ENV') !== 'production', true, true);
        // Slim middleware is LIFO — the LAST added runs FIRST. CORS must be
        // added after routing/error so it is outermost: otherwise the routing
        // middleware 405s an OPTIONS preflight (no OPTIONS routes are
        // registered) before CorsMiddleware can short-circuit it, and the
        // browser blocks every cross-origin JSON/Authorization request.
        $app->add(new CorsMiddleware(self::corsOrigins()));

        // Per-admin JWT gate (replaces the shared ADMIN_TOKEN for the UI) and a
        // generic any-session gate for /me + /password.
        $adminJwt = new JwtAuthMiddleware(
            $container->get(JwtService::class),
            $container->get(SessionRepository::class),
            requireAdmin: true,
        );
        $sessionAuth = new JwtAuthMiddleware(
            $container->get(JwtService::class),
            $container->get(SessionRepository::class),
        );
        // Service-to-service token for the customer-api onboarding call. Falls
        // back to the legacy ADMIN_TOKEN so existing deployments keep working
        // until SERVICE_TOKEN is set.
        $service = new AdminAuthMiddleware(self::env('SERVICE_TOKEN', self::env('ADMIN_TOKEN', '')));

        $app->get('/healthz', HealthAction::class);

        // Unified login (both panels) + back-compat alias.
        $app->post('/login', LoginAction::class);
        $app->post('/customer/login', LoginAction::class);

        // Logout (works for any session) + back-compat alias.
        $app->delete('/logout', AdminLogoutAction::class);
        $app->delete('/admin/login', AdminLogoutAction::class);

        // Current principal + password change (any authenticated user).
        $app->get('/me', MeAction::class)->add($sessionAuth);
        $app->put('/password', ChangePasswordAction::class)->add($sessionAuth);
        $app->put('/customer/password', ChangePasswordAction::class)->add($sessionAuth);

        // User management (per-admin JWT).
        $app->get('/admin/users', ListUsersAction::class)->add($adminJwt);
        $app->post('/admin/users', CreateUserAction::class)->add($adminJwt);
        $app->patch('/admin/users/{id}', UpdateUserAction::class)->add($adminJwt);
        $app->delete('/admin/users/{id}', DeleteUserAction::class)->add($adminJwt);
        $app->post('/admin/users/{id}/reset-password', ResetPasswordAction::class)->add($adminJwt);

        // Session inspection (per-admin JWT).
        $app->get('/admin/sessions', ListSessionsAction::class)->add($adminJwt);
        $app->delete('/admin/sessions/{jti}', RevokeSessionAction::class)->add($adminJwt);

        // Server-to-server onboarding (service token).
        $app->post('/admin/customer-credentials', CreateCustomerCredentialAction::class)->add($service);

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
