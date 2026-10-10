# RUNBOOK — tds-auth-api

Operational steps that are not code and cannot be automated from CI.

## After deploying 0.7.0 (Gruppen, Firmenadmin, Kontingente, Rechte-Entzug)

### 1. Audit the stored permissions — BEFORE the deploy reaches users

`Permissions::sanitize()` used to intersect with nine hardcoded portal keys on
**write and on read**. Anything granted outside that set over the last year is
already in the database and was merely being dropped on load. Removing the read
filter hands those rights to the people who hold them.

```sql
-- Anything stored that is NOT one of the nine original portal keys.
SELECT user_id, company_id, permissions
  FROM app_user_company
 WHERE permissions REGEXP '"[a-z0-9-]+:[a-z0-9-]+"'
   AND permissions NOT REGEXP
       '^\[?("(projects:read|invoices:read|invoices:pay|documents:read|documents:write|messages:read|messages:write|tickets:read|tickets:write)",?)*\]?$';
```

Run the same against `app_user.permissions`. Expect to see the composed
extensions' keys (`companies:*`, `time:*`, `wiki:*`) — those are the grants the
old code was silently discarding, and they are the point of the change. Anything
you do NOT recognise, clean up before the deploy.

### 2. Switch delegation ON for the company — FIRST

Since 0.7.0 a company can only have company admins if it has been granted them:
`auth_company_policy.allow_company_admins`. A company with no policy row at all
counts as **not granted**, which is every company after the migration.

*Benutzer* → **Firmen-Kontingente** → pick the company → *Firmenadmins zulassen*.
Or directly:

```sql
INSERT INTO auth_company_policy (company_id, allow_company_admins)
VALUES (<id>, 1)
ON DUPLICATE KEY UPDATE allow_company_admins = 1;
```

**Do this before step 3.** In the other order the promotion is refused
(`422 delegation_disabled`) — and if an older row already carries
`is_company_admin = 1`, it simply grants nothing: the resolver folds the flag
away and `/company/*` answers `403 delegation_disabled`. Nothing is broken, but
nothing works either, and there is no error to find.

### 3. Promote the first company admin of each company

Every `app_user_company.is_company_admin` starts at `0`, so no company can
manage itself until a platform admin promotes someone. **Without this step the
whole feature looks broken** — `/firma` is invisible and `/company/*` answers
403 for everyone.

Through the admin frontend: *Benutzer* → edit the user → the company's
membership → **Firmenadmin**. Or directly:

```sql
UPDATE app_user_company SET is_company_admin = 1
 WHERE user_id = <id> AND company_id = <id>;
-- Their token still says otherwise until it is reissued:
UPDATE session SET revoked_at = NOW() WHERE user_id = <id> AND revoked_at IS NULL;
```

More than one per company is fine and expected. A company with **zero** company
admins is a valid state too — it simply means nobody administers it from inside;
the platform admin still can, through the same screens.

### 4. (Optional) Set a policy per company

A company with no `auth_company_policy` row is unrestricted — that is today's
behaviour and a perfectly good end state. Set one only where you actually want a
seat cap or a ceiling: *Benutzer* → **Firmen-Kontingente**.

Remember `null` ≠ `[]` for `allowed_permissions`: `null` means "no ceiling",
`[]` means "may grant nothing".

## Consolidating the two `customer` tables (prerequisite, still open)

`tds_customer.customer` (legacy) and `tds_frontend.company` (canonical) both
exist. Until the copy below has run, `lib/companies.ts` in the frontend host
keeps its legacy fallback.

```sql
INSERT INTO tds_frontend.company (id, name, email, phone, note, created_at, updated_at)
SELECT id, name, NULLIF(email,''), phone, note, created_at, NOW()
  FROM tds_customer.customer;
ALTER TABLE tds_frontend.company AUTO_INCREMENT = <max(id)+1>;
```

`NULLIF` matters: the legacy `email` is `NOT NULL UNIQUE`, the composed one is
`NULL UNIQUE`, and an empty string would collide on the unique index.

**Then verify — this must return 0:**

```sql
SELECT COUNT(DISTINCT company_id) FROM tds_auth.app_user_company
 WHERE company_id NOT IN (SELECT id FROM tds_frontend.company);
```

A non-zero result means memberships point at companies that do not exist in the
canonical table; fix that before deleting the legacy fallback, or portal users
lose their company.
