# Agent notes — tds-auth-api

PHP 8.3 + Slim 4 + firebase/php-jwt. Issues and verifies RS256
JWTs. Other backends verify them via `/.well-known/jwks.json`
without ever seeing the private key.

## Behind the gateway

The public surface `api.tracht-digital.de/auth/*` is fronted by
`tds-api-gateway`, a Slim reverse proxy that strips the `/auth` prefix and
forwards to this service (so `…/auth/admin/login` → this app's
`/admin/login`). The path contract is unchanged — routes here still mount at
root. The build model is dev/release (see README): a push to `main` auto-assembles the **`dev`** bundle (developer artifact, not deployed); the manual **Release** workflow (`release.yml`) assembles the **`release`** bundle, pings the deploy webhook, and fires a `repository_dispatch(api-pushed)` to the gateway (needs `GATEWAY_DISPATCH_TOKEN`) so it reassembles its `dev` bundle.

## Endpoints

Unified user model: one `app_user` row = one login spanning both panels.
`is_admin` grants admin-panel access; a non-null `customer_id` ties the
account to a company (tenant) in the portal, scoped by a `permissions` JSON
array (the catalog is hand-duplicated in `Domain\Permissions` from tds-shared's
`PORTAL_PERMISSIONS`). Multiple accounts may share one `customer_id`. The JWT
carries `admin`, `customer_id`, `uid` and `permissions`. (The old
`customer_credential` table is left in place for rollback but is no longer
read.)

- `POST /login` (alias `POST /customer/login`) — email + password → JWT for
  both panels. Looks up `app_user`, verifies with `password_verify` (dummy
  verify on miss for constant-time behavior), rejects `disabled` accounts with
  403. Response includes `isAdmin` / `customerId` / `permissions`; the admin
  panel checks `isAdmin`.
- `DELETE /logout` (alias `DELETE /admin/login`) — revoke session + clear
  cookie (works for any session).
- `GET /me` — current principal (drives UI gating). Gated by `JwtAuthMiddleware`.
- `PUT /password` (alias `PUT /customer/password`) — change own password,
  rotate session. Gated by `JwtAuthMiddleware`.
- `GET|POST /admin/users`, `PATCH|DELETE /admin/users/{id}`,
  `POST /admin/users/{id}/reset-password` — user management, gated by
  `JwtAuthMiddleware(requireAdmin: true)` (per-admin JWT, not the shared
  token). Authorization-relevant changes (is_admin / permissions / status /
  customer_id) revoke the user's sessions so the change lands on next login.
- `GET /admin/sessions`, `DELETE /admin/sessions/{jti}` — same admin-JWT gate.
- `POST /admin/customer-credentials` — server-to-server, gated by the
  **service token** (`SERVICE_TOKEN`, falls back to `ADMIN_TOKEN`). Called by
  tds-customer-api after a company row is inserted; creates the matching
  `app_user` (full portal access by default).
- `POST /refresh` — rotate access token, carrying `uid`/`permissions` forward
  (verifies signature + session revocation).
- `GET /.well-known/jwks.json` — public key in JWKS format.

Bootstrap the first admin (the shared-token paste login is gone):

```bash
composer create-admin -- you@example.com [password]
```

## Key generation

Run once per environment:

```bash
composer keygen
```

Writes `keys/private.pem` (mode 600) and `keys/public.pem`. Copy the
private key contents into `.env` as `JWT_PRIVATE_KEY=` (single line,
literal `\n` escapes if needed). Public key is committed to the repo
so the JWKS endpoint can serve it.

**Don't ever commit `keys/private.pem`.** The .gitignore covers it,
the deploy workflow excludes it from the upload, but the convention
is: private key only ever exists in (a) your password manager, (b)
the production host `.env`, (c) optionally `keys/private.pem` on the dev
machine. After step (a), feel free to `rm` the file.

## Mental model

- `JwtService` issues + verifies with the loaded keys.
- `SessionRepository` records every issued JWT's `jti` for revocation
  on logout. JWKS verification alone won't catch a logged-out token —
  the consumer would need to call us to check, which we don't do
  yet. For now, logout works inside the auth domain (refresh stops
  working), and other services accept tokens until natural expiry.
- `CookieFactory` builds `Domain=.tracht-digital.de` cookies so the
  same JWT works across `admin.` and `app.` subdomains.

## Tests

PHPUnit 10. `composer test` runs the suite.

- **JwtService** — issue/verify round-trip, RS256 signature, iss/exp
  enforcement, JWK extraction. `tests/Support/Keys` generates a
  throwaway 2048-bit RSA keypair per test run via `openssl_pkey_new`,
  so the real `JWT_PRIVATE_KEY` never appears in the suite.
- Most actions/middleware are driven directly with Slim PSR-7 objects plus
  `FakeSessionRepository` + `FakeAppUserRepository` (no DB) — `LoginAction`,
  `MeAction`, `ChangePasswordAction`, the `Admin\Users\*` CRUD,
  `JwtAuthMiddleware`, `CreateCustomerCredentialAction`, plus `CookieFactory`,
  `AdminAuthMiddleware`, `JwksAction`, `RefreshAction`, `Admin\LogoutAction`,
  `Domain\Permissions`, `PasswordGenerator`.
- **Integration tests** (`PdoSessionRepository`, `PdoRateLimiter`) exercise
  real MariaDB. Set `TDS_TEST_DB_DSN` (+ `_USER` / `_PASS`) to run; otherwise
  they skip. The `app_user` migration + `PdoAppUserRepository` SQL are only
  exercised end-to-end against a real DB (`composer migrate` + manual run).

See INSTALL.md §7 for the throwaway-Docker test DB recipe.

## Don't

- Don't issue JWTs without recording the jti in `session`. Future
  revocation depends on it.
- Don't log the JWT_PRIVATE_KEY anywhere. error_log is fine for
  generic error messages but never include the key.
- Don't increase JWT_TTL_SECONDS beyond ~3600 without thinking about
  blast-radius of a leaked token.
- Don't write `$_ENV[$key] ?? getenv($key) ?: $default` in env
  helpers. PHP binds `??` tighter than `?:`, so this parses as
  `($_ENV[$key] ?? getenv($key)) ?: $default` and silently
  clobbers any legitimately falsy value (`"0"`, `""`) with the
  default. Use explicit `?? false` checks instead. Bit all four
  API repos at once via copy-paste — see #11 (this repo) /
  contact #7 / content #13 / customer #13.
