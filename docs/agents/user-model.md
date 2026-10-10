# User model, companies and permissions

## There is no "Kunde" person: only users and the companies they belong to

`customer` always meant a **company**; people were always `app_user`. The schema says so:
`app_user_customer` → **`app_user_company`**, every `customer_id` → **`company_id`**, and the Firmen
extension's rights `customers:*` → **`companies:*`**.

**Both spellings are accepted for one transition release:** the `customer_id` JWT claim is still emitted,
`PermissionAliases` normalises old permission ids on read, and `?customer_id=` / `customerId` are still
read in payloads. A token minted before a deploy carries the old claim for up to an hour, and services
verify independently. **The follow-up release deletes the aliases.** (`session.customer_id` was renamed
too; see [database.md](database.md#a-db-test-that-writes-its-own-ddl-only-tests-itself).)

## One login, several companies

- One `app_user` row is one login across both products. `is_admin` grants admin-frontend access.
- Portal access is a set of **memberships** in `app_user_company`; each carries its own `permissions` JSON.
- `app_user.company_id` + `permissions` are the denormalised **primary** membership (default active
  company), kept in sync with the first membership by `PdoAppUserRepository::setMemberships`. Several
  accounts may share a company. Membership is optional (none, one or several).
- The old `customer_credential` table stays for rollback but is no longer read.

## JWT claims

`admin`, `support_agent`, `company_id` (primary), `uid`, `permissions` (primary), **`companies`**
(`[{id, permissions, admin}]`, resolved values), `email` and `name`.

- `email` / `name` are **identity, not authorisation**; nothing gates on them. They exist so consumers
  can label a request without calling back (`tds-core-frontend-api`'s `UserContext::email()`). `name` is
  `AppUser::label()`: `display_name`, else `name`, else email.
- The `companies` shape stays exact, so every consumer's RBAC works unchanged. Shipping group ids would
  force every consumer to resolve groups. A group edit therefore reaches users on their next token, which
  is why write paths revoke the members' sessions.
- The portal picks one active company per session; consuming services enforce that company's permissions.

## Permissions are validated by shape, never filtered on read

`Permissions::sanitize()` validates the **shape** of a permission id, not a catalog, and runs **on write
only**; `hydrate()` returns what is stored, in input order.

- The authoritative catalog belongs to the service that enforces it (the composed API's
  `GET /admin/permissions`). `UserContext::has()` is an exact string match, so an unknown key grants
  nothing: inert, not lost.
- No catalog table is synced here (it would go stale in the dangerous direction), and login never calls
  the composed API (**login must not depend on another service**).
- **Filtering on read must not come back**; it lets a catalog change retroactively rewrite the database.

## Groups (`auth_group`, `auth_user_group`)

Real rows, seeded from the former UI presets with permission lists **hard-coded in the migration** (a
migration never imports a moving constant).

- **`company_id = 0` means platform-wide** and is NOT NULL (MySQL treats NULLs as distinct in a unique
  index).
- **The assignment carries the company**, not the membership: "Buchhaltung" at A, "Nur Lesen" at B.
- **Companies may own groups** if `auth_company_policy.allow_custom_groups`, capped by the same ceiling.
- **No assignments were backfilled**; inferring a group from a matching permission set is a guess.
- **"Vermittler"** (`referral_partner`, 2026-10-11) carries only `referrals:partner` for the
  Empfehlungsprogramm. A partner still needs a company membership; permissions live in the per-company
  claim.

## Effective permissions

**`(direct ∪ groups) minus denies, then ∩ ceiling`** — `EffectivePermissions`, a pure function.

- **Per-person denies** sit on one membership (one source, one scope), so "why can't this person do X" has
  one answer. A deny beats a group grant; the ceiling beats everything. A deny needs no ceiling check on
  write (it only reduces), which is why `permissionDenies` is company-editable and `permissionCeiling`
  isn't.
- **Ceiling ≠ denies.** The ceiling is the platform admin's delegation limit; denies are the current
  decision about a person.
- **The ceiling is intersected at token-issue time**, not only on grant, so lowering a company's
  `allowed_permissions` actually lowers access.

### `PermissionResolver` must be used everywhere

It was once registered but injected nowhere: groups granted nothing and the ceiling never applied on
issue. Every path that publishes a membership (all login paths, `MeAction`, refresh) goes through
`PermissionResolver::effective()`. `tests/Service/PermissionResolverTest.php` asserts against an
**issued and verified token**. Route any new membership-publishing path through it.

## Company admins: `/company/{companyId}/*`

Gated by `CompanyAdminMiddleware` (after `JwtAuthMiddleware`; Slim is LIFO). Passes for a platform admin,
or for a `companies[]` entry with `admin: true` **whose company has delegation on**.

- **Delegation is a per-company grant** (`allow_company_admins`, default **false**, also without a policy
  row). Off → `403 delegation_disabled`, `is_company_admin` folds to false everywhere, and the platform
  editor refuses to set the flag (`422 delegation_disabled`).
- The middleware reads that flag **from the database** on each request, so switching it off takes effect
  immediately. Platform admins bypass it.
- **Scoped by the path, not `X-Act-As-*`**: auth-api's CORS doesn't carry that header, and the tenant
  belongs in the access log.
- `ATTR_COMPANY_ID` is namespaced (`tds.companyId`); Slim publishes route args as attributes and would
  overwrite a plain `companyId`.

### `CompanyUserGuard`

| Guard | Why |
|---|---|
| Target must be a member → **404** | 403 would confirm the account exists |
| Never touch a platform admin | Otherwise a company admin can disable the platform's administrator |
| Field whitelist → **422**, loudly | Silently dropping `isAdmin` returns 200 to a broken or probing client. `permissionCeiling` isn't on the list |
| Ceiling covers **groups** too | Otherwise a platform group carrying the forbidden key bypasses it |
| Last company admin → **409** | Mirrors the platform self-lockout guard |
| Delete removes the **membership** | Deleting the account would also remove it from other companies |
| Seat cap under `SELECT … FOR UPDATE` | Prevents two concurrent creates taking the last seat |

- **Seats count disabled users** (else "disable one, add another" is a free seat).
- **No policy row = unrestricted.** `max_users: null` is unlimited; `allowed_permissions: null` is no
  ceiling, `[]` is "may grant nothing".
- **After deploying: enable delegation for the company, then promote its first company admin.** The other
  order is refused. See `RUNBOOK.md`.

## Account flags

- **`is_support_agent`** marks admins that tickets can be assigned to. Only sticks on admins
  (`CreateUserAction` / `UpdateUserAction` coerce it to false otherwise and clear it on demotion). Rides
  the JWT as `support_agent`; surfaced as `isSupportAgent` on `/login` and `/me`.
- **`is_blog_author`** marks a login allowed to author blog posts, independent of `is_admin` (admins are
  implicit authors). JWT claim `blog_author`; `isBlogAuthor` on `/login` and `/me`. Profile fields
  `avatar_url` and `bio` support the public author page.
- Toggling either flag revokes the user's sessions so the claim refreshes.
