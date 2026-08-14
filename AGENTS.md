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

> ## There is no "Kunde" person — only Benutzer, and Firmen they may belong to
>
> `customer` was always the word for a **company**; people were always
> `app_user`. Having both words in the schema is what made the product look
> like it had two kinds of people. As of 0.6.0 the schema says what it means:
> `app_user_customer` → **`app_user_company`**, every `customer_id` →
> **`company_id`**, and the Firmen extension's rights `customers:*` →
> **`companies:*`**.
>
> **`session.customer_id` was renamed too, and the repository did not follow —
> which broke every login until 0.7.2.** See *A DB test that writes its own DDL
> only ever tests itself* below before renaming anything else.
>
> **Both spellings are still accepted for ONE release** — the `customer_id`
> JWT claim is still emitted, `PermissionAliases` normalises the old permission
> ids on read, and `?customer_id=` / `customerId` are still read in payloads.
> That is not politeness: a token minted five minutes before the deploy carries
> the old claim for up to an hour, and every service verifies independently, so
> they do not all switch at the same instant. **The follow-up release deletes
> the aliases** — leaving them means the old name works forever and the rename
> bought nothing.

Unified user model: one `app_user` row = one login spanning both frontends.
`is_admin` grants admin-frontend access; portal access is a set of **company
memberships** in `app_user_company` — a login can belong to **several**
companies, each with its own `permissions` JSON array.
`app_user.company_id` + `permissions` are the
denormalised **primary** membership (the default active company), kept in sync
with the first membership row by `PdoAppUserRepository::setMemberships`. Multiple
accounts may share a company. The JWT carries `admin`, `support_agent`,
`company_id` (primary), `uid`, `permissions` (primary), **`companies`**
(the full membership list `[{id, permissions, admin}]`) and — since 0.5.0 — `email`
and `name`; the portal picks one active company per session and customer-api
enforces that company's permissions. (The old `customer_credential` table is
left in place for rollback but is no longer read.)

`email` / `name` are **identity, not authorization** — nothing gates on them.
They exist because every consuming service already verifies this token and
would otherwise need a call back here just to label a request in a log or a
header: `tds-core-frontend-api`'s `JwtUserContext` has read `$claims['email']`
since it was written, the claim never existed, and so `UserContext::email()`
was permanently `null` across the entire composed backend. `name` is
`AppUser::label()` — `display_name`, else `name`, else the email — resolved
once here so no consumer invents its own fallback and renders a blank header.

> **`Permissions::sanitize()` validates the SHAPE now, not a catalog — and
> nothing filters on READ any more.** It used to intersect with nine hardcoded
> portal keys on write *and* on hydrate, so every one of the thirteen composed
> extensions' permissions (`companies:read`, `time:read`, `wiki:write`) was
> accepted by the UI, written to the database, and silently dropped again on
> load. An admin ticked a box, saw it save, and the user never got the right.
>
> The authoritative catalog belongs to the service that ENFORCES it (the
> composed API's `GET /admin/permissions`); `UserContext::has()` is an exact
> string match, so an unrecognised key grants nothing anywhere. The failure mode
> moves from **silent data loss** to **inert data**.
>
> Deliberately not solved by syncing a catalog table here — a second source of
> truth that goes stale in the dangerous direction, where a newly composed
> extension stays ungrantable until a sync runs — nor by calling the composed
> API: **login must never depend on a service that has been down for weeks.**
>
> **Filtering on read is the part that must not come back.** It means a catalog
> change retroactively rewrites what the database says. `hydrate()` returns what
> is stored; `sanitize()` runs on write only, and its output is now in INPUT
> order (the old `array_intersect` silently re-sorted to catalog order).
>
> ⚠ **Audit the rows before deploying.** Anything granted over the last year
> outside those nine keys is already IN the database and was only being dropped
> on read — removing the read filter hands it to people. The audit query is in
> the Phase 2 plan; eyeball it and clean anything unexpected in the same
> migration.

## Groups, company admins and quotas (0.7.0)

**Groups are real rows now.** `PORTAL_ROLE_PRESETS` in tds-shared was UI sugar:
the editor expanded one into a flat array on click and nothing recorded which
preset was used, so editing a "role" later changed nothing for anyone already
carrying it. `auth_group` + `auth_user_group` replace it, seeded from exactly
those four (with the permission lists **hard-coded in the migration** — a
migration must never import a moving constant).

- **`company_id = 0` means platform-wide**, and is NOT nullable: MySQL treats
  NULLs as distinct in a unique index, so a nullable column would accept two
  platform groups with the same slug.
- **The ASSIGNMENT carries the company**, not the membership row. A login in two
  companies routinely needs "Buchhaltung" at A and "Nur Lesen" at B.
- **Companies may own groups**, gated on `auth_company_policy.allow_custom_groups`
  and capped by the same ceiling — otherwise a custom group is a trivial way
  around it: put the forbidden right in a group, assign the group.
- **No assignments are backfilled.** Inferring "this user's set equals preset X,
  so give them the group" is a guess that would silently change their access the
  first time someone edits the group.

**Effective permissions = `(direct ∪ groups) minus denies, then ∩ ceiling`**
(`EffectivePermissions`, a pure function — the whole model is testable without a
DB).

**Per-person denies (0.7.0) reverse an earlier "no deny rules, ever".** That
objection is about denies attached to ROLES, which compose: two groups, one
granting and one denying, and the outcome hangs on precedence nobody remembers.
A deny here sits on one membership — one source, one scope — so "why can this
person not do X" keeps a single answer, and the editor shows it next to the
group it overrides. The alternative people reach for is cloning a group for one
person, which silently stops tracking the original. Order is fixed: a deny beats
a group grant, the ceiling beats everything. **A deny needs no ceiling check on
write** — it can only reduce, which is also why `permissionDenies` is on the
company-scoped field whitelist while `permissionCeiling` is not.

**`permissionCeiling` and `permissionDenies` are different things** and the
easy mistake is to treat them as one. The ceiling is the platform admin's limit
on delegation — the most this person may ever be granted, unraisable by a
company admin. The denies are the current decision about the person, editable by
whoever manages them.

**The ceiling is intersected at TOKEN-ISSUE time, not only when granting.**
Checking it only on write would make it a one-time gate — lower a company's
`allowed_permissions` afterwards and every already-assigned group keeps
out-granting it. Intersecting on issue is what makes a lowered ceiling actually
lower anything.

**The JWT keeps its exact shape**: `companies: [{id, permissions, admin}]`
carries RESOLVED values, so `JwtUserContext` in the composed API and all
thirteen extensions' RBAC work unchanged — no contract change, no coordinated
deploy. Shipping group ids instead would make every consumer learn what a group
is and re-resolve it against a database it does not have. The cost is that a
group edit reaches a user on their next token, which is why the write paths
revoke the members' sessions.

### The delegated surface: `/company/{companyId}/*`

Gated by `CompanyAdminMiddleware` (after `JwtAuthMiddleware`; Slim is LIFO).
Passes for a platform admin, or for a `companies[]` entry with `admin: true`
**whose company has delegation switched on**.

**Delegation is a per-company grant (`allow_company_admins`, 0.7.0).** Without
it nobody inside the company creates or manages users or assigns groups: the
route answers `403 delegation_disabled`, the resolver folds `is_company_admin`
to false everywhere it is published, and the platform user editor refuses to set
the flag at all (`422 delegation_disabled`) rather than storing something inert.
It defaults to **false**, including for a company with no policy row — unlike
every limit in that table, this field hands a capability out rather than capping
one, so an unconfigured company must not have it.

The middleware reads that one flag **from the database**, which its docblock
used to say it never does. Session revocation covers people who already hold a
token, but this is the switch that says "nobody administers this company from
inside", and a switch that takes up to an hour to mean anything is not a switch.
A platform admin bypasses it entirely — it limits what a company may do on its
own, not what the platform may do to it.

- **Scoped by the PATH, not `X-Act-As-*`.** auth-api's CORS allow-list does not
  carry that header, and widening it on the service that holds the keypair to
  save a path segment is a bad trade — plus a company id inferred from ambient
  state does not appear in the access log, and a destructive route should say
  out loud which tenant it acted on.
- **`ATTR_COMPANY_ID` is namespaced (`tds.companyId`).** Slim publishes every
  route argument as a request attribute under its own name, so a plain
  `companyId` is silently overwritten by the route's raw string — and `(int) "7"`
  still works, which is why this would have gone unnoticed for a long time.

Every write obeys `CompanyUserGuard`, and each rule is a boundary rather than a
nicety:

| Guard | Why |
|---|---|
| target must be a member → **404** | 403 would confirm the account exists, making the route an existence oracle for other companies' users |
| never touch a platform admin | otherwise a company admin can disable the account that administers the platform |
| field whitelist → **422**, loudly | silently dropping `isAdmin` means a broken (or probing) client gets a 200 and believes it worked. `permissionCeiling` is absent from the list, which is what stops a company admin raising their own |
| ceiling covers **groups too** | else: assign a platform group containing the forbidden key, ceiling bypassed without ever naming it |
| last company admin → **409** | mirrors the platform's self-lockout guard; otherwise only a platform admin can restore access |
| delete removes the MEMBERSHIP | a login can belong to several companies — deleting the account because company A is done with them takes away company B, silently, from a route that named only A |
| seat cap under `SELECT … FOR UPDATE` | a plain count-then-insert lets two concurrent creates both take the last seat |

**Seats count DISABLED users too.** Otherwise "disable one, add another" is a
free seat, which is the first thing anyone tries.

**A company with no policy row is unrestricted** — exactly today's behaviour, so
the feature is opt-in per company rather than a migration everyone must survive.
`max_users: null` = unlimited; `allowed_permissions: null` = no ceiling, but
`[]` = "may grant nothing", and collapsing those two would make locking a
company down unexpressible.

> **Two manual steps after deploying, in this order:** switch delegation on for
> the company, THEN promote its first company admin (every `is_company_admin`
> starts `0`). In the other order the promotion is refused; and a pre-existing
> flag on a company without the grant simply does nothing, with no error to
> find. Several company admins per company are fine, and zero is a valid state —
> it just means nobody administers it from inside. See `RUNBOOK.md`.

### The resolver had no consumers for a whole release

`PermissionResolver` was registered in `Bootstrap` and injected **nowhere**: all
four login paths called `issueForUser($user)` with no resolver, and `MeAction`
returned the raw membership row. So groups granted nothing, and the ceiling was
enforced on write and never on issue — the exact one-time gate the design
argues against. Nothing was red because nothing looked.

Everything that publishes a membership now goes through
`PermissionResolver::effective()`, and `tests/Service/PermissionResolverTest.php`
asserts against an **issued and verified token**, not against the resolver in
isolation: a unit test of the rule proves nothing about whether the issuer uses
it. If you add a path that hands a membership outside this service, route it
through the resolver.

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
- **Self-service profile — `PATCH /me`, `POST|DELETE /me/avatar`,
  `GET /me/sessions`, `DELETE /me/sessions/{jti}`.** All gated by
  `JwtAuthMiddleware` (any session) and all targeting **the user in the token**;
  none of them takes a user id. Three things here are deliberate:
  - **`PATCH /me` accepts exactly one field, `displayName`.** Not `name` (it is
    the account name an admin maintains and it drives the public blog byline —
    a different decision from picking a nickname for your own header), not
    `email` (login identity, uniquely indexed, needs a confirmation flow), and
    none of the flags. Unknown keys are ignored rather than 422'd, because the
    obvious client mistake is POSTing back a whole `/me` object. Nothing here
    is authorization-relevant, so **no sessions are revoked** — that is why the
    action has no `SessionRepository` at all, and a test pins the constructor
    arity so one cannot quietly appear.
  - **`DELETE /me/sessions/{jti}` proves ownership first and answers 404, not
    403, for someone else's session.** `SessionRepository::revoke()` revokes
    whatever jti it is handed and knows nothing about owners, so the check
    lives here via `ownerOf()`. A 403 would confirm the jti exists, turning the
    route into an existence oracle; unknown, foreign, already-revoked and
    expired all answer identically. Revoking your *own* current session is
    allowed — that is just logging out from the session list.
  - **`GET /me/sessions` scopes in SQL** (`listActiveForUser`), not by filtering
    `listActive()` in PHP, which would hand a self-service caller every other
    user's rows first. `current: true` marks the requesting session, without
    which "Abmelden" on an unlabelled row is a coin flip.
- **`GET /users/{id}/avatar` is UNAUTHENTICATED, by necessity.** A cross-origin
  `<img src>` sends no credentials, and the panel (`management.`/`app.`) is a
  different origin from this service (`api.`), so a session-gated avatar simply
  would not render; the alternative — inlining every avatar as a data URL —
  would put the bytes in every `/me` response and defeat HTTP caching. What it
  exposes is a picture the person chose as their public representation, which
  already appears on the public blog's author pages, and a user id with no
  avatar is indistinguishable from one that does not exist (both 404).
  **The bytes live in `app_user_avatar` (MEDIUMBLOB), not on disk** — same
  reasoning as `cms_legal_doc` in tds-ext-website-cms-pkg: no writable
  directory on the Plesk host, which is this platform's chronic go-live
  blocker. `app_user.avatar_url` had pointed at the archived tds-content-api's
  `/uploads` since 20260707000001, so there was no working upload path at all.
  Uploads are **sniffed with `getimagesizefromstring`, never trusted from the
  part's `Content-Type`**, and **SVG is rejected** — it is a document that can
  carry `<script>`, and this file is served from the origin the session cookie
  is scoped to. There is no server-side resizing (no guaranteed `ext-gd`); the
  panel downscales in a `<canvas>` first and 2 MiB is the ceiling for a client
  that skipped it. The public URL is built from **`JWT_ISSUER`** rather than a
  new env var, precisely because a fourth thing to keep in sync across
  `install.php` / `docker-entrypoint.sh` / `.env.example` is how hosts break here.
- `GET|POST /admin/users`, `PATCH|DELETE /admin/users/{id}`,
  `POST /admin/users/{id}/reset-password` — user management, gated by
  `JwtAuthMiddleware(requireAdmin: true)` (per-admin JWT, not the shared
  token). Authorization-relevant changes (is_admin / is_support_agent /
  permissions / status / customer_id) revoke the user's sessions so the change
  lands on next login.
- `GET /admin/sessions`, `DELETE /admin/sessions/{jti}` — same admin-JWT gate.
  **`session.created_at` is `DATETIME(6)` and `record()` writes `NOW(6)`.** That is
  load-bearing, not tidiness: at 1-second resolution any two sessions issued in the same
  second tied, and `listActive()`'s sort fell through to its `jti` tiebreaker — a random
  UUIDv4. The order was deterministic but unrelated to recency, so "newest first" was
  simply untrue (a refresh plus a passkey sign-in land in the same second routinely).
  Writing `NOW()` again would silently reinstate it, and the hand-written DDL in
  `tests/Infrastructure/PdoSessionRepositoryTest.php` has to stay at `(6)` too — at
  second resolution that suite passes green while production ordering stays broken.
- `POST /admin/customer-credentials` — server-to-server, gated by the
  **service token** (`SERVICE_TOKEN`, falls back to `ADMIN_TOKEN`). Called by
  tds-customer-api after a company row is inserted; creates the matching
  `app_user` (full portal access by default).
- `POST /refresh` — rotate access token, carrying `uid`/`permissions`/`email`/
  `name` forward (verifies signature + session revocation).
  **A non-admin with no company membership is legitimate here.** This used to
  `throw new \RuntimeException('non-admin without customer_id')`, i.e. a 500 —
  and `LoginAction` never checked, so such an account signed in fine and then
  broke an hour later on its first refresh, in the worst possible shape: the
  panel's backstop saw a 500 while `/me` still answered 200, so the session
  neither recovered nor ended and the user degraded in place. Company
  membership is optional by design (none, one, or several).
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

## "Angemeldet bleiben" (30 Tage) — a refresh, not a longer token

`POST /login` accepts `{"remember": true}` and issues a SECOND httpOnly cookie
(`tds_remember`, `Domain=.tracht-digital.de`) backed by `app_user_remember`.

**Why not simply lengthen the JWT.** Every other service verifies the session
token against the JWKS and never talks to this database, so a JWT's lifetime is
also its **non-revocability** window: a 30-day JWT means a disabled account keeps
working for 30 days. The JWT therefore stays at an hour, and staying signed in
becomes an exchange at `POST /refresh`, which re-reads the user and mints a token
from their *current* flags and memberships.

Shape (`Service\RememberTokenService`): the cookie is `selector:validator`. The
selector is what the row is found by, so the lookup never compares a secret; only
a SHA-256 of the validator is stored, compared with `hash_equals`. **The pair
rotates on every use** — a copied cookie works at most once before the real
browser's next refresh invalidates it, so theft surfaces as an unexpected logout
instead of 30 days of silent access. A wrong validator against a *real* selector
deletes the row outright.

Four ways a remembered login ends, and only one of them is a revocation:

| Event | Mechanism |
|---|---|
| Logout | `LogoutAction` forgets the presented cookie + expires it |
| Own password change | `ChangePasswordAction` forgets **all** of the user's tokens (revoking sessions alone would be theatre — the untrusted device still holds a 30-day cookie) |
| Disabled / deleted account, admin password reset | Caught in `RefreshAction`, which re-reads the user each time and refuses on `!isActive()` or `mustChangePassword` |
| Natural expiry | `expires_at` |

**The panels must call `/refresh`** or none of this is reachable: the host's
pre-paint gate and `frontendFetch` try it on a `/me` 401 before treating the
session as dead (`tds-core-frontend-pkg`).

## Passkeys (WebAuthn)

`lbuchs/webauthn` — dependency-free apart from ext-openssl, which fits the
platform's lean-dependency convention. Six routes: `POST /passkeys/login/options`
+ `POST /passkeys/login` (unauthenticated by definition), and `GET /passkeys`,
`POST /passkeys/options`, `POST /passkeys`, `DELETE /passkeys/{id}` behind the
session gate.

Three decisions worth not re-litigating:

- **The RP ID is the registrable domain** (`tracht-digital.de`), not the login
  host. An origin satisfies an RP ID when the RP ID is a registrable-domain
  suffix of it, so one passkey covers `auth.` / `management.` / `app.` / `tools.`.
  Registering under `auth.tracht-digital.de` would silently produce passkeys that
  work only there. Override with `WEBAUTHN_RP_ID`.
- **Discoverable (resident) credentials only, and no `allowCredentials` at
  login.** Sign-in carries no email — the authenticator names the account. That
  removes the account-enumeration surface an email-keyed `allowCredentials` list
  would create, and it is what makes the flow typing-free. Registration therefore
  passes `requireResidentKey: true`; a non-discoverable credential would register
  fine and then be unusable to log in with.
- **The challenge lives in a signed cookie** (`Service\ChallengeStore`), because
  this API keeps no session. The challenge is not a secret; the HMAC exists so a
  client cannot *choose* one it already holds a signature for. Single-use — every
  terminal path expires it.

`sign_count` is stored so a *decreasing* counter can be rejected (WebAuthn's only
clone signal). Many modern authenticators always report 0, so zero is normal and
must not be treated as an attack — the comparison only happens when both sides
are non-zero. Attestation is `none`: TDS does not restrict authenticators, and
asking for attestation would collect device identifiers to no purpose.

Passkey login is otherwise the ordinary login path — same JWT, same session
record, same cookies, same optional "angemeldet bleiben". A passkey replaces the
password, not the session model.

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

- **MembershipPayload** — the parser behind the company assignment in
  `POST`/`PATCH /admin/users/{id}`. It decides which companies a portal login
  belongs to and which permissions it holds in each, from untrusted editor
  input, so it is asserted to DROP nonsense rather than store it: a
  non-positive `customerId`, a membership entry that is not an object, an
  unknown permission key (which would otherwise ride the JWT and be compared
  verbatim by every consumer), and permissions sent without a company.
  The subtle half is `present()`, which lets an update tell **"the request said
  nothing about memberships"** (leave them alone) from **"the request
  explicitly cleared them"** (`memberships: []` → revoke every company).
  Collapsing those two either strands a user with access an admin just removed,
  or wipes the memberships of every user edited for an unrelated reason. Both
  directions are pinned. Verified by mutation: 18 breakages, 18 caught.

- **MigrationDialectTest** — a static scan of `db/migrations/*.php` that fails
  when a column named in a `primary_key` table option is not declared
  `'null' => false`. See "Migrations must survive MySQL 8" below; it needs no
  database and runs in every suite.

See INSTALL.md §7 for the throwaway-Docker test DB recipe.

## Migrations must survive MySQL 8 (0.7.1)

**The prod host is MySQL 8. Dev, CI and every DB-backed test here run
MariaDB 11, which is markedly more permissive.** A migration can therefore be
green in every place anyone looks and still be impossible to apply where it
matters.

Phinx defaults every `addColumn()` to **nullable**. A table declared with
`'primary_key' => ['user_id']` whose `user_id` column does not say so itself
emits a nullable PRIMARY KEY column. MariaDB silently coerces it to NOT NULL;
MySQL 8 refuses:

```
SQLSTATE[42000] 1171 All parts of a PRIMARY KEY must be NOT NULL
```

`app_user_avatar` (20260813000001) and `auth_company_policy` (20260814000005)
both shipped that way. Nothing was red, because nothing ran them on MySQL 8 —
the first and only symptom was the gateway's `/install.php` dying on a fresh
host at *"Migration: auth"* with fourteen migrations applied, ten not, and no
way for the installer to continue. Fixed in **0.7.1**; both now carry
`'null' => false` with the reason next to them.

Two guards, deliberately both:

| Guard | Where | Catches |
|---|---|---|
| `tests/Support/MigrationDialectTest` | this repo's suite | the known trap, instantly, with no DB |
| *Migrate against MySQL 8* step | `_pipeline.yml`, every run | everything else — it proves the result rather than reading the source |

The CI step runs a `mysql:8` service alongside the MariaDB one (host port 3307)
and applies the whole set to an empty database before any bundle is published.
It works without a `.env` because **`phinx.php` now falls back to `getenv()`**:
PHP's default `variables_order` (`GPCS`) leaves `$_ENV` unpopulated from the
real environment, so reading `$_ENV` alone would have silently migrated the
default database instead. Note the precedence — a real `.env` still wins, which
is what the host relies on.

The gateway repeats the same rehearsal across **all** services
(`tds-gateway-api/scripts/check-migrations-mysql8.php`, run during the
assemble), because the composed frontend's 13 extensions have no PHP suite of
their own.

**Editing an already-applied migration is fine here and only here:** MariaDB
had coerced the column to NOT NULL anyway, so a host that already ran it has
the identical schema. Never change a released migration's *version*.

> **Windows gotcha.** The WinGet PHP build ships no active `openssl.cnf`, so
> `openssl_pkey_new` in `tests/Support/Keys` fails with
> `error:80000003:system library::No such process` and **53 tests error out** —
> nothing to do with the code. Point PHP at the bundled config for the run:
>
> ```bash
> OPENSSL_CONF="$(ls -d ~/AppData/Local/Microsoft/WinGet/Packages/PHP.PHP.8.3*/extras/ssl/openssl.cnf)" \
>   vendor/bin/phpunit
> ```

## A DB test that writes its own DDL only ever tests itself (0.7.2)

Migration 20260814000001 renamed `session.customer_id` to `company_id`.
`PdoSessionRepository` kept writing the old name in three statements, so:

```
SQLSTATE[42S22] 1054 Unknown column 'customer_id' in 'field list'
```

**Every successful login returned 500** — `POST /login` records the jti right
after the password check — while a *wrong* password still returned a clean 401,
because it returns before a session is ever recorded. That asymmetry is the
whole signature: the login form rejected bad credentials correctly and answered
correct ones with a server error, which reads like a password problem and is
not one. `GET /me/sessions` and `GET /admin/sessions` were dead the same way.

**Why the suite was green.** Not a skipped test: the DB-backed tests DO run in
CI against a real MariaDB. `PdoSessionRepositoryTest` builds its own `session`
table with hand-written DDL, and that DDL still said `customer_id` — so it
created the pre-rename schema, asserted against it, and passed. The suite was
testing a table that exists nowhere else. (`tds-content-api` has the same trap
recorded for its blog-post repository; the lesson did not travel.)

Two guards, deliberately both:

| Guard | Where | Catches |
|---|---|---|
| `tests/Support/RenamedColumnSqlTest` | this repo's suite, **no DB needed** | any SQL literal naming a retired identifier |
| the `setUp()` comment in `PdoSessionRepositoryTest` | that suite | the hand-written DDL drifting from the migrations again |

`RenamedColumnSqlTest` inspects **only string literals that are themselves SQL**
(they carry a `SELECT`/`INSERT`/`FROM`/… keyword). That precision is the point:
`customer_id` legitimately survives elsewhere as the deprecated JWT claim, the
`?customer_id=` query alias and the `customer_credential` table, none of which
it may flag. Add to its `RETIRED` map whenever a migration renames something.

**When you rename a column, grep the repositories in the same change.** The
migration is the easy half; the SQL that reads and writes it is in another file
and no tool connects the two.

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
