# Sessions, tokens, passkeys and keys

## Mental model

- `JwtService` issues and verifies with the loaded keys.
- `SessionRepository` records every issued JWT's `jti` for revocation. Other services verify via JWKS only,
  so a logged-out token stays valid elsewhere until it expires; that is why the TTL stays around an hour.
- `CookieFactory` builds `Domain=.tracht-digital.de` cookies, so one session works across all subdomains.
- The login UI lives in `tds-auth-frontend` (`auth.tracht-digital.de`), which calls `/login`, `/me` and
  `/password` cross-origin with credentials.

## CORS

The first-party `*.tracht-digital.de` surfaces (incl. `auth.`) are a **hard-coded baseline in
`corsOrigins()`**, merged with `CORS_ALLOWED_ORIGINS` (which only adds, e.g. `http://localhost:4321`). A
missing env var once left zero allowed origins and blocked every login preflight.

## `POST /refresh`

Rotates the access token, carrying `uid`, `permissions`, `email` and `name` forward (verifies signature
and session revocation). It re-reads the user and refuses on `!isActive()` or `mustChangePassword`.

**`auth_time` is the session's identity.** Every token carries the sign-in time (OIDC `auth_time`);
refresh copies it, a login or a remembered re-login stamps a new one. `jti` and `iat` rotate hourly and
cannot answer "since sign-in". The panel's setup wizard snoozes items until the next `auth_time`.

**A non-admin without a company membership is legitimate.** Refresh used to throw (500) for such accounts
while login succeeded, leaving users degraded an hour after sign-in.

## "Angemeldet bleiben" (30 days): a refresh, not a longer token

`POST /login` with `{"remember": true}` issues a second httpOnly cookie (`tds_remember`,
`Domain=.tracht-digital.de`) backed by `app_user_remember`.

**Why not a longer JWT:** other services never talk to this database, so a JWT's lifetime is its
non-revocability window. The JWT stays at an hour; staying signed in is an exchange at `POST /refresh`,
which mints from the user's **current** flags and memberships.

`Service\RememberTokenService`: the cookie is `selector:validator`. Rows are found by selector; only a
SHA-256 of the validator is stored and compared with `hash_equals`. **The pair rotates on every use**, so a
stolen cookie works at most once before the real browser invalidates it. A wrong validator for a real
selector deletes the row.

| Event | Mechanism |
|---|---|
| Logout | `LogoutAction` forgets the presented cookie and expires it |
| Own password change | `ChangePasswordAction` forgets **all** the user's tokens |
| Disabled / deleted account, admin password reset | `RefreshAction` re-reads the user and refuses |
| Natural expiry | `expires_at` |

**The panels must call `/refresh`** on a `/me` 401 before treating the session as dead (the host's
pre-paint gate and `frontendFetch` in `tds-core-frontend-pkg`).

## Passkeys (WebAuthn)

`lbuchs/webauthn` (dependency-free apart from ext-openssl). Routes: `POST /passkeys/login/options` and
`POST /passkeys/login` (unauthenticated), plus `GET /passkeys`, `POST /passkeys/options`, `POST /passkeys`,
`DELETE /passkeys/{id}` behind the session gate.

- **The RP ID is the registrable domain** (`tracht-digital.de`), so one passkey covers every subdomain.
  Registering under `auth.tracht-digital.de` would produce passkeys that only work there. Override with
  `WEBAUTHN_RP_ID`.
- **Discoverable credentials only, no `allowCredentials` at login.** Sign-in carries no email (no account
  enumeration, no typing). Registration passes `requireResidentKey: true`.
- **The challenge lives in a signed cookie** (`Service\ChallengeStore`), because the API keeps no session.
  The HMAC stops clients choosing a challenge; it is single-use.
- `sign_count` is stored so a *decreasing* counter is rejected, but only when both sides are non-zero
  (many authenticators always report 0).
- Attestation is `none`; TDS doesn't restrict authenticators.
- A passkey login is otherwise the ordinary login: same JWT, session record, cookies and remember option.

## Keys

`composer keygen` writes `keys/private.pem` (mode 600) and `keys/public.pem`. Put the private key into
`.env` as `JWT_PRIVATE_KEY=` (single line, literal `\n` escapes if needed). The public key is committed so
the JWKS endpoint can serve it.

**Never commit `keys/private.pem`** (it is gitignored and excluded from deploys). The private key lives only
in the password manager, the production `.env` and optionally on the dev machine. Never log it.
