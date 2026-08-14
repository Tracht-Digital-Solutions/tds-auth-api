<?php
declare(strict_types=1);

namespace Tds\AuthApi;

use DI\Container;
use Dotenv\Dotenv;
use PDO;
use Slim\App;
use Slim\Factory\AppFactory;
use Slim\Routing\RouteCollectorProxy;
use Tds\AuthApi\Action\Admin\CreateCustomerCredentialAction;
use Tds\AuthApi\Action\Admin\ListSessionsAction;
use Tds\AuthApi\Action\Admin\LogoutAction as AdminLogoutAction;
use Tds\AuthApi\Action\Admin\RevokeSessionAction;
use Tds\AuthApi\Action\Admin\Users\CreateUserAction;
use Tds\AuthApi\Action\Admin\Users\DeleteUserAction;
use Tds\AuthApi\Action\Admin\Users\ListUsersAction;
use Tds\AuthApi\Action\Admin\Users\ResetPasswordAction;
use Tds\AuthApi\Action\Admin\Users\UpdateUserAction;
use Tds\AuthApi\Action\Admin\Companies\CompanyPolicyAction;
use Tds\AuthApi\Action\Admin\Companies\SaveCompanyPolicyAction;
use Tds\AuthApi\Action\Admin\Groups\CreateGroupAction;
use Tds\AuthApi\Action\Admin\Groups\DeleteGroupAction;
use Tds\AuthApi\Action\Admin\Groups\ListGroupsAction;
use Tds\AuthApi\Action\Admin\Groups\UpdateGroupAction;
use Tds\AuthApi\Action\Company\CompanyGroupAction;
use Tds\AuthApi\Action\Company\CreateCompanyUserAction;
use Tds\AuthApi\Action\Company\ListCompanyUsersAction;
use Tds\AuthApi\Action\Company\RemoveCompanyUserAction;
use Tds\AuthApi\Action\Company\UpdateCompanyUserAction;
use Tds\AuthApi\Action\ChangePasswordAction;
use Tds\AuthApi\Action\DeleteAvatarAction;
use Tds\AuthApi\Action\HealthAction;
use Tds\AuthApi\Action\JwksAction;
use Tds\AuthApi\Action\ListMySessionsAction;
use Tds\AuthApi\Action\LoginAction;
use Tds\AuthApi\Action\MeAction;
use Tds\AuthApi\Action\RefreshAction;
use Tds\AuthApi\Action\RevokeMySessionAction;
use Tds\AuthApi\Action\ShowAvatarAction;
use Tds\AuthApi\Action\UpdateMeAction;
use Tds\AuthApi\Action\UploadAvatarAction;
use Tds\AuthApi\Infrastructure\Database;
use Tds\AuthApi\Action\Passkey\DeleteAction as DeletePasskeyAction;
use Tds\AuthApi\Action\Passkey\ListAction as ListPasskeysAction;
use Tds\AuthApi\Action\Passkey\LoginOptionsAction as PasskeyLoginOptionsAction;
use Tds\AuthApi\Action\Passkey\PasskeyLoginAction;
use Tds\AuthApi\Action\Passkey\RegisterAction as RegisterPasskeyAction;
use Tds\AuthApi\Action\Passkey\RegisterOptionsAction as PasskeyRegisterOptionsAction;
use Tds\AuthApi\Infrastructure\PdoAppUserRepository;
use Tds\AuthApi\Infrastructure\PdoAvatarRepository;
use Tds\AuthApi\Infrastructure\PdoCompanyPolicyRepository;
use Tds\AuthApi\Infrastructure\PdoGroupRepository;
use Tds\AuthApi\Infrastructure\PdoPasskeyRepository;
use Tds\AuthApi\Infrastructure\PdoRememberTokenRepository;
use Tds\AuthApi\Infrastructure\PdoSessionRepository;
use Tds\AuthApi\Middleware\AdminAuthMiddleware;
use Tds\AuthApi\Middleware\CompanyAdminMiddleware;
use Tds\AuthApi\Middleware\CorsMiddleware;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\AvatarRepository;
use Tds\AuthApi\Service\AvatarService;
use Tds\AuthApi\Service\ChallengeStore;
use Tds\AuthApi\Service\CompanyPolicyRepository;
use Tds\AuthApi\Service\GroupRepository;
use Tds\AuthApi\Service\PermissionResolver;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\PasskeyRepository;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Service\PdoRateLimiter;
use Tds\AuthApi\Service\RateLimiter;
use Tds\AuthApi\Service\RememberCookieFactory;
use Tds\AuthApi\Service\RememberTokenRepository;
use Tds\AuthApi\Service\RememberTokenService;
use Tds\AuthApi\Service\SessionRepository;
use Tds\AuthApi\Service\WebAuthnFactory;

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

        // The group repository is injected so a hydrated membership carries its
        // `groupIds` — the user editor needs them, and without it the editor
        // would show every user as belonging to no group.
        $container->set(AppUserRepository::class, fn (Container $c) => new PdoAppUserRepository(
            $c->get(PDO::class),
            $c->get(GroupRepository::class),
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

        // "Angemeldet bleiben". Same attributes as the session cookie, different
        // name and lifetime — see RememberTokenService for why this is a
        // separate credential rather than a longer-lived JWT.
        $container->set(RememberCookieFactory::class, fn () => new RememberCookieFactory(new CookieFactory(
            name: self::env('REMEMBER_COOKIE_NAME', 'tds_remember'),
            domain: self::env('COOKIE_DOMAIN', '.tracht-digital.de'),
            secure: self::env('APP_ENV') === 'production',
        )));

        $container->set(RememberTokenRepository::class, fn (Container $c) => new PdoRememberTokenRepository($c->get(PDO::class)));

        $container->set(AvatarRepository::class, fn (Container $c) => new PdoAvatarRepository($c->get(PDO::class)));

        $container->set(GroupRepository::class, fn (Container $c) => new PdoGroupRepository($c->get(PDO::class)));
        $container->set(CompanyPolicyRepository::class, fn (Container $c) => new PdoCompanyPolicyRepository($c->get(PDO::class)));

        // (direct ∪ groups) \ denies ∩ ceiling, plus the company's delegation
        // grant folded into the admin flag — what a token and /me may claim.
        // PHP-DI autowires it into the four issuers and MeAction; it was
        // registered here and injected NOWHERE for a release, which is how
        // groups came to grant nothing at all.
        $container->set(PermissionResolver::class, fn (Container $c) => new PermissionResolver(
            $c->get(GroupRepository::class),
            $c->get(CompanyPolicyRepository::class),
        ));

        // The avatar's public URL is built from JWT_ISSUER — this service's own
        // public base, already written by all three env writers (the gateway's
        // install.php, deploy/docker-entrypoint.sh and .env.example). A
        // dedicated AVATAR_BASE_URL would be a fourth thing to keep in sync,
        // and a missing env value in one writer is exactly how this platform
        // has broken hosts before.
        $container->set(AvatarService::class, fn () => new AvatarService(
            publicBase: self::env('JWT_ISSUER', 'https://api.tracht-digital.de/auth'),
        ));

        $container->set(PasskeyRepository::class, fn (Container $c) => new PdoPasskeyRepository($c->get(PDO::class)));

        // Passkeys. The RP ID is the REGISTRABLE DOMAIN, not the login host, so
        // one passkey works on auth./management./app./tools. — see WebAuthnFactory.
        $container->set(WebAuthnFactory::class, fn () => new WebAuthnFactory(
            rpName: self::env('WEBAUTHN_RP_NAME', 'Tracht Digital Solutions'),
            rpId: self::env('WEBAUTHN_RP_ID', 'tracht-digital.de'),
        ));

        // The WebAuthn challenge lives in a signed cookie because this API is
        // stateless (no PHP session). Its secret falls back to a hash of the JWT
        // private key so no new required config appears on existing hosts — the
        // challenge is not a secret, it only must not be attacker-chosen.
        $container->set(ChallengeStore::class, fn () => new ChallengeStore(
            secret: self::env('WEBAUTHN_CHALLENGE_SECRET', '') !== ''
                ? self::env('WEBAUTHN_CHALLENGE_SECRET')
                : hash('sha256', self::loadPrivateKey($rootDir)),
            cookieName: self::env('WEBAUTHN_COOKIE_NAME', 'tds_wa_challenge'),
            domain: self::env('COOKIE_DOMAIN', '.tracht-digital.de'),
            secure: self::env('APP_ENV') === 'production',
        ));

        $container->set(RememberTokenService::class, fn (Container $c) => new RememberTokenService(
            repository: $c->get(RememberTokenRepository::class),
            // The checkbox says 30 days; JWT_REFRESH_TTL_SECONDS already carried
            // that value and was otherwise unused.
            ttlSeconds: (int) self::env('REMEMBER_TTL_SECONDS', self::env('JWT_REFRESH_TTL_SECONDS', (string) (60 * 60 * 24 * 30))),
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

        // Self-service profile. Everything here targets the user in the TOKEN;
        // none of these routes take a user id. See UpdateMeAction for the
        // (deliberately short) list of fields a user may change about
        // themselves and why `name`, `email` and every flag are excluded.
        $app->patch('/me', UpdateMeAction::class)->add($sessionAuth);
        $app->post('/me/avatar', UploadAvatarAction::class)->add($sessionAuth);
        $app->delete('/me/avatar', DeleteAvatarAction::class)->add($sessionAuth);
        $app->get('/me/sessions', ListMySessionsAction::class)->add($sessionAuth);
        $app->delete('/me/sessions/{jti}', RevokeMySessionAction::class)->add($sessionAuth);

        // Public avatar read. Unauthenticated BY NECESSITY: a cross-origin
        // <img src> sends no credentials, so a session-gated avatar would
        // simply not render in the panel. See ShowAvatarAction.
        $app->get('/users/{id:[0-9]+}/avatar', ShowAvatarAction::class);

        // User management (per-admin JWT).
        $app->get('/admin/users', ListUsersAction::class)->add($adminJwt);
        $app->post('/admin/users', CreateUserAction::class)->add($adminJwt);
        $app->patch('/admin/users/{id}', UpdateUserAction::class)->add($adminJwt);
        $app->delete('/admin/users/{id}', DeleteUserAction::class)->add($adminJwt);
        $app->post('/admin/users/{id}/reset-password', ResetPasswordAction::class)->add($adminJwt);

        // Permission groups (platform). A group is a real row now, not the
        // client-side preset expansion it used to be — editing one changes what
        // its members may do, which is why the write paths revoke sessions.
        $app->get('/admin/groups', ListGroupsAction::class)->add($adminJwt);
        $app->post('/admin/groups', CreateGroupAction::class)->add($adminJwt);
        $app->patch('/admin/groups/{id:[0-9]+}', UpdateGroupAction::class)->add($adminJwt);
        $app->delete('/admin/groups/{id:[0-9]+}', DeleteGroupAction::class)->add($adminJwt);

        // Per-company limits the platform admin imposes: seats, the ceiling on
        // what may be granted, and whether the company may define its own
        // groups. A company with no policy is unrestricted — the feature is
        // opt-in per company.
        $app->get('/admin/companies/{companyId:[0-9]+}/policy', CompanyPolicyAction::class)->add($adminJwt);
        $app->put('/admin/companies/{companyId:[0-9]+}/policy', SaveCompanyPolicyAction::class)->add($adminJwt);

        // --- The delegated company-admin surface ---------------------------
        //
        // Scoped by the PATH, not a header: the target company has to be
        // explicit in the access log, and auth-api's CORS allow-list does not
        // carry `X-Act-As-*` (widening it on the service that holds the
        // keypair, to save a path segment, is a bad trade).
        //
        // Slim middleware is LIFO — the LAST `add()` runs FIRST — so the JWT
        // gate is added last and CompanyAdminMiddleware sees the claims it
        // attached.
        $companyAdmin = new CompanyAdminMiddleware($container->get(CompanyPolicyRepository::class));

        $app->group('/company/{companyId:[0-9]+}', function (RouteCollectorProxy $group): void {
            $group->get('/users', ListCompanyUsersAction::class);
            $group->post('/users', CreateCompanyUserAction::class);
            $group->patch('/users/{id:[0-9]+}', UpdateCompanyUserAction::class);
            $group->delete('/users/{id:[0-9]+}', RemoveCompanyUserAction::class);

            // Company-owned groups, gated additionally on the policy's
            // `allow_custom_groups`.
            $group->post('/groups', CompanyGroupAction::class);
            $group->patch('/groups/{id:[0-9]+}', CompanyGroupAction::class);
            $group->delete('/groups/{id:[0-9]+}', CompanyGroupAction::class);
        })->add($companyAdmin)->add($sessionAuth);

        // Session inspection (per-admin JWT).
        $app->get('/admin/sessions', ListSessionsAction::class)->add($adminJwt);
        $app->delete('/admin/sessions/{jti}', RevokeSessionAction::class)->add($adminJwt);

        // Server-to-server onboarding (service token).
        $app->post('/admin/customer-credentials', CreateCustomerCredentialAction::class)->add($service);

        // Passkeys (WebAuthn). The two login routes are unauthenticated by
        // definition; the rest manage the signed-in user's own credentials.
        // Registration options + finish are session-gated: you add a passkey to
        // the account you are already signed into.
        $app->post('/passkeys/login/options', PasskeyLoginOptionsAction::class);
        $app->post('/passkeys/login', PasskeyLoginAction::class);
        $app->get('/passkeys', ListPasskeysAction::class)->add($sessionAuth);
        $app->post('/passkeys/options', PasskeyRegisterOptionsAction::class)->add($sessionAuth);
        $app->post('/passkeys', RegisterPasskeyAction::class)->add($sessionAuth);
        $app->delete('/passkeys/{id:[0-9]+}', DeletePasskeyAction::class)->add($sessionAuth);

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

    /**
     * Allowed CORS origins = a hardcoded baseline of the first-party
     * *.tracht-digital.de production surfaces, merged with any extra origins from
     * CORS_ALLOWED_ORIGINS (deduped). The baseline means the central login site
     * and every sibling frontend can POST /login + read /me (both with
     * credentials) even if the host `services/auth/.env` is unset or stale — a
     * missing var used to leave zero allowed origins, so the browser blocked the
     * login preflight and the form reported "Netzwerkfehler". The env only ADDS
     * (e.g. http://localhost:4321 for dev). Mirrors tds-core-frontend-api.
     *
     * @return string[]
     */
    private static function corsOrigins(): array
    {
        // Use the safe env() helper — NOT the `?? getenv() ?: ''` one-liner the
        // comment above warns against (the `??`-binds-tighter-than-`?:` trap).
        $baseline = [
            'https://tracht-digital.de',
            'https://blog.tracht-digital.de',
            'https://auth.tracht-digital.de',
            'https://management.tracht-digital.de',
            'https://app.tracht-digital.de',
            'https://tools.tracht-digital.de',
        ];
        $raw = self::env('CORS_ALLOWED_ORIGINS', '');
        $extra = array_filter(array_map('trim', explode(',', $raw)));
        return array_values(array_unique([...$baseline, ...$extra]));
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
