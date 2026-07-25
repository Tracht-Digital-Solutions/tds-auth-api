# Agent notes — tds-auth-api

PHP 8.3 + Slim 4 + firebase/php-jwt. Issues and verifies RS256
JWTs. Other backends verify them via `/.well-known/jwks.json`
without ever seeing the private key.

> Status: **core dependency of BOTH architectures — never superseded.** The legacy
> backends *and* the new `tds-core-frontend-api` verify against this service's JWKS; the
> frontend host logs in and edits users (`/admin/users`, memberships) against it. See the
> root `MIGRATION-STATUS.md`.

## Behind the gateway

The public surface `api.tracht-digital.de/auth/*` is fronted by
`tds-gateway-api`, a Slim reverse proxy that strips the `/auth` prefix and
forwards to this service (so `…/auth/admin/login` → this app's
`/admin/login`). The path contract is unchanged — routes here still mount at
root. The build model is dev/release (see README): a push to `main` auto-assembles the **`dev`** bundle (developer artifact, not deployed); the manual **Release** workflow (`release.yml`) assembles the **`release`** bundle, pings the deploy webhook, and fires a `repository_dispatch(api-pushed)` to the gateway (needs `GATEWAY_DISPATCH_TOKEN`) so it reassembles its `dev` bundle.

## Endpoints

Unified user model: one `app_user` row = one login spanning both frontends.
`is_admin` grants admin-frontend access; portal access is a set of **company
memberships** in `app_user_customer` — a login can belong to **several**
companies, each with its own `permissions` JSON array (catalog hand-duplicated
in `Domain\Permissions` from tds-shared-pkg's `PORTAL_PERMISSIONS` — includes
`tickets:read`/`tickets:write`). `app_user.customer_id` + `permissions` are the
denormalised **primary** membership (the default active company), kept in sync
with the first membership row by `PdoAppUserRepository::setMemberships`. Multiple
accounts may share a company. The JWT carries `admin`, `support_agent`,
`customer_id` (primary), `uid`, `permissions` (primary) and **`companies`**
(the full membership list `[{id, permissions}]`); the portal picks one active
company per session and customer-api enforces that company's permissions. (The
old `customer_credential` table is left in place for rollback but is no longer
read.)

`is_support_agent` marks the subset of **admins** that support tickets can be
assigned to (the "Bearbeiter", read by tds-customer-api / tds-admin). It only
sticks on admin accounts — `CreateUserAction` / `UpdateUserAction` coerce it to
`false` for non-admins and clear it when an admin is demoted. It rides the JWT
as the `support_agent` claim (only for admins), is surfaced on `POST /login` +
`GET /me` (`isSupportAgent`), and toggling it revokes the user's sessions so the
claim refreshes on next login.

`is_blog_author` marks a login that may **author blog posts** (parallel to
`is_support_agent` but **independent of `is_admin`** — a non-admin can hold it;
admins are implicitly authors). It rides the JWT as the `blog_author` claim so
tds-content-api can gate blog writes without a lookup, is surfaced on `/login` +
`/me` (`isBlogAuthor`), and toggling it revokes sessions. Two profile fields sit
alongside it for the public blog author page: `avatar_url` (a plain URL string —
the image file itself is uploaded to tds-content-api's `/uploads`, auth-api just
keeps the URL) and `bio`. Both are set via user CRUD (`avatarUrl` / `bio`) and
returned by `/me` + the user list.

- `POST /login` (alias `POST /customer/login`) — email + password → JWT for
  both frontends. Looks up `app_user`, verifies with `password_verify` (dummy
  verify on miss for constant-time behavior), rejects `disabled` accounts with
  403. Response includes `isAdmin` / `customerId` / `permissions`; the admin
  frontend checks `isAdmin`.
- `DELETE /logout` (alias `DELETE /admin/login`) — revoke session + clear
  cookie (works for any session).
- `GET /me` — current principal (drives UI gating). Gated by `JwtAuthMiddleware`.
  Includes `expiresAt` (Unix seconds, from the verified token's `exp` claim, or
  `null` if absent) so the frontends' inline gate can bounce an *expired* session to
  `/login` before the frontend paints instead of flashing it and redirecting only
  after the first 401.
- `PUT /password` (alias `PUT /customer/password`) — change own password.
  Revokes **all** the user's existing sessions (not just the caller's jti — a
  password change must terminate a lost/stolen device, which could otherwise
  keep refreshing for the 30-day refresh TTL) and issues a fresh session for
  the current device so the caller stays logged in. Gated by `JwtAuthMiddleware`.
- `GET|POST /admin/users`, `PATCH|DELETE /admin/users/{id}`,
  `POST /admin/users/{id}/reset-password` — user management, gated by
  `JwtAuthMiddleware(requireAdmin: true)` (per-admin JWT, not the shared
  token). Authorization-relevant changes (is_admin / is_support_agent /
  permissions / status / customer_id) revoke the user's sessions so the change
  lands on next login.
- `GET /admin/sessions`, `DELETE /admin/sessions/{jti}` — same admin-JWT gate.
- `POST /admin/customer-credentials` — server-to-server, gated by the
  **service token** (`SERVICE_TOKEN`, falls back to `ADMIN_TOKEN`). Called by
  tds-customer-api after a company row is inserted; creates the matching
  `app_user` (full portal access by default).
- `POST /refresh` — rotate access token, carrying `uid`/`permissions` forward
  (verifies signature + session revocation).
- `GET /.well-known/jwks.json` — public key in JWKS format.

Bootstrap the first admin (the shared-token paste login is gone). Two paths,
both flag the account `must_change_password` so the first login is forced
through the change-password screen before the frontend opens:

- **Seed migration** (`20260701000002_seed_bootstrap_admin`): on the first
  `composer migrate`, if no admin exists yet, seeds ONE admin from
  `ADMIN_BOOTSTRAP_EMAIL` / `ADMIN_BOOTSTRAP_PASSWORD` (defaults
  `admin@tracht-digital.de` / `tds-setup-admin`). Idempotent — skips when an
  admin already exists or the email is taken. This is the no-SSH setup path.
- **Script** (manual): `composer create-admin -- you@example.com [password]`.

The `must_change_password` flag is surfaced by `POST /login` + `GET /me`
(`mustChangePassword`) and cleared by `PUT /password`. An admin-issued temp
password (generated on user-create, or `POST /reset-password`) sets it too, so
any handed-out credential forces the recipient to pick their own.

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
  same JWT works across `management.` and `app.` subdomains.
- **Central login** — the login/password-change UI lives in `tds-auth-frontend`
  (`auth.tracht-digital.de`); this API stays UI-less (JSON only). That site
  POSTs `/login`, reads `/me`, PUTs `/password` cross-origin with credentials.
  The first-party `*.tracht-digital.de` surfaces (incl. `auth.`) are a **hardcoded
  baseline in `corsOrigins()`**, merged with `CORS_ALLOWED_ORIGINS` (which only
  ADDS, e.g. `http://localhost:4321`). The baseline means the login works even if
  the host `services/auth/.env` omits the var — a missing var used to leave zero
  allowed origins, so the browser blocked the login preflight and the form showed
  "Netzwerkfehler" (mirrors `tds-core-frontend-api`). Because the session cookie is
  already `Domain=.tracht-digital.de`, a login there is immediately valid on every
  sibling frontend — no token hand-off.

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
- Don't add `CorsMiddleware` before `addRoutingMiddleware()`. Slim
  middleware is LIFO — the LAST added runs FIRST — so CORS must be added
  AFTER routing/error to be outermost. Added earlier, the routing
  middleware 405s every OPTIONS preflight (no OPTIONS routes exist) before
  CORS can short-circuit it, and browsers block every cross-origin
  JSON/Authorization request, including the frontend logins. Bit all four API
  repos at once via copy-paste; `tests/PreflightTest.php` (an OPTIONS
  request through the REAL `Bootstrap::createApp()` app) is the regression
  guard — unit-testing the middleware alone cannot catch the ordering.
- Don't run `php -S` without `public/router.php` (`composer start` passes
  it). Without a router script the built-in server 404s any dotted path
  that has no file on disk — `/.well-known/jwks.json` never reaches Slim
  and every consumer's JWT verification breaks. Apache (.htaccess) and the
  gateway's in-process mode don't need it.
