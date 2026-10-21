# Testing

PHPUnit 10; `composer test` runs the suite. INSTALL.md §7 has the throwaway-Docker test DB recipe.

## Unit (no DB)

- **`JwtService`** — issue/verify round trip, RS256, `iss` / `exp`, JWK extraction. `tests/Support/Keys`
  generates a throwaway 2048-bit RSA keypair per run, so the real key never appears.
- Actions and middleware driven with Slim PSR-7 objects plus `FakeSessionRepository` /
  `FakeAppUserRepository`: `LoginAction`, `MeAction`, `ChangePasswordAction`, `Admin\Users\*`,
  `JwtAuthMiddleware`, `CreateCustomerCredentialAction`, `CookieFactory`, `AdminAuthMiddleware`,
  `JwksAction`, `RefreshAction`, `Admin\LogoutAction`, `Domain\Permissions`, `PasswordGenerator`.
- **`MembershipPayload`** — drops nonsense from untrusted editor input; `present()` separates "said
  nothing" from "cleared". Mutation check: 18/18 caught.
- **`tests/Service/PermissionResolverTest.php`** — asserts against an issued and verified token.
- **`MigrationDialectTest`**, **`RenamedColumnSqlTest`** — static scans (see [database.md](database.md)).
- **`tests/Infrastructure/TimeZoneTest`** — session time-zone pinning.
- **`tests/PreflightTest.php`** — OPTIONS through the real app.

## Integration (real MariaDB)

`PdoSessionRepository`, `PdoRateLimiter`. Set `TDS_TEST_DB_DSN` (+ `_USER` / `_PASS`); otherwise they skip.
The `app_user` migration and `PdoAppUserRepository` SQL are exercised only against a real DB.

Hand-written test DDL must match the migrations (see [database.md](database.md)).

## Windows

The WinGet PHP build ships no active `openssl.cnf`, so `openssl_pkey_new` fails
(`error:80000003:system library::No such process`) and ~53 tests error out. Point PHP at the bundled
config:

```bash
OPENSSL_CONF="$(ls -d ~/AppData/Local/Microsoft/WinGet/Packages/PHP.PHP.8.3*/extras/ssl/openssl.cnf)" \
  vendor/bin/phpunit
```

## CI

`_pipeline.yml` also applies all migrations to an empty `mysql:8` service on every run.

Build model: a push to `main` assembles the `dev` bundle (not deployed); the manual Release assembles
`release`, pings the deploy webhook and dispatches `api-pushed` to the gateway (`GATEWAY_DISPATCH_TOKEN`).
