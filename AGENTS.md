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

- `POST /admin/login` — Phase-2 bridge: shared ADMIN_TOKEN → JWT.
- `DELETE /admin/login` — revoke session + clear cookie (works for
  either admin or customer JWTs — the route name is historical).
- `POST /admin/customer-credentials` — server-to-server, gated by
  AdminAuthMiddleware. Called by tds-customer-api after a customer
  row is inserted; we argon2id-hash the temp password into
  `customer_credential`.
- `POST /customer/login` — email + password → customer JWT. Looks
  up `customer_credential`, verifies with `password_verify`, runs a
  dummy verify on miss for constant-time behavior.
- `POST /refresh` — rotate access token (verifies signature + checks
  session revocation).
- `GET /.well-known/jwks.json` — public key in JWKS format.

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
- **CookieFactory**, **AdminAuthMiddleware**, **JwksAction**,
  **RefreshAction**, **Admin\\LoginAction**, **Admin\\LogoutAction**
  — driven directly with Slim PSR-7 objects and a
  `FakeSessionRepository`. No DB.
- **Integration tests** (`Customer\\LoginAction`,
  `Admin\\CreateCustomerCredentialAction`,
  `PdoSessionRepository`) exercise real MariaDB. Set
  `TDS_TEST_DB_DSN` (+ `_USER` / `_PASS`) to run; otherwise they skip.

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
