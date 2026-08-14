<?php
declare(strict_types=1);

namespace Tds\AuthApi\Domain;

/**
 * What counts as a permission key.
 *
 * ### This used to be a catalog, and that was the bug
 *
 * `ALL` held nine portal keys and `sanitize()` INTERSECTED with it — on write
 * *and* on read. The panel meanwhile composes thirteen extensions, each
 * contributing its own permissions (`companies:read`, `time:read`,
 * `wiki:write`), so granting one through `PATCH /admin/users/{id}` wrote it to
 * the database and then dropped it again on every load. An admin ticked a box,
 * saw it saved, and the user never got the right.
 *
 * The authoritative catalog belongs to the service that ENFORCES it — the
 * composed API publishes it at `GET /admin/permissions`. auth-api is an
 * identity store, not the authorization decision point, and `UserContext::has()`
 * is an exact string match, so a key nobody recognises grants nothing anywhere.
 * Validating the shape turns the failure mode from **silent data loss** into
 * **inert data**, which is the correct trade.
 *
 * Deliberately NOT solved by syncing the catalog into a table here: that is a
 * second source of truth which goes stale in the dangerous direction (a newly
 * composed extension stays ungrantable until a sync runs — the same silent
 * failure with a longer fuse). And deliberately not by calling the composed
 * API: login must never depend on a service that has been down for weeks.
 *
 * `PORTAL_SEED` is what the nine keys are FOR now: seeding the system groups
 * and acting as the admin editor's offline fallback catalog.
 */
final class Permissions
{
    /**
     * The original portal keys. Hand-duplicated from tds-shared-pkg's
     * `PORTAL_PERMISSIONS`; kept in step the same way every other Zod ↔ PHP
     * pair here is.
     *
     * @var list<string>
     */
    public const PORTAL_SEED = [
        'projects:read',
        'invoices:read',
        'invoices:pay',
        'documents:read',
        'documents:write',
        'messages:read',
        'messages:write',
        'tickets:read',
        'tickets:write',
    ];

    /**
     * `resource:action`, lowercase, hyphens allowed inside each half.
     * Mirrors `PERMISSION_KEY_PATTERN` in tds-shared-pkg/src/permissions.
     *
     * A wildcard is not a valid key on purpose: `*` would grant every FUTURE
     * extension's permission, which is exactly the escalation the per-company
     * ceilings exist to prevent.
     */
    public const KEY_PATTERN = '/^[a-z0-9][a-z0-9-]{0,31}:[a-z0-9][a-z0-9-]{0,31}$/';

    /**
     * Upper bound on one grant. The resolved set rides in the JWT, which rides
     * in a cookie; unbounded, that is a request-header size limit waiting to
     * be hit in production.
     */
    public const MAX_KEYS = 128;

    /** @deprecated The nine keys are a seed set, not the catalog. Use {@see self::PORTAL_SEED}. */
    public const ALL = self::PORTAL_SEED;

    public static function isValid(string $key): bool
    {
        return preg_match(self::KEY_PATTERN, $key) === 1;
    }

    /**
     * Keep the well-formed keys, drop the rest.
     *
     * **Order is INPUT order, not catalog order** — the old implementation
     * returned `array_intersect(self::ALL, …)`, which silently re-sorted every
     * array to the catalog's sequence. Nothing depended on that, but a test
     * pins it so nobody "restores" the intersection while thinking they are
     * fixing the sort.
     *
     * Applied on WRITE only. Sanitizing on read means a catalog change
     * retroactively rewrites what the database says, which is precisely how a
     * legitimately granted key vanished from a token without any write ever
     * happening.
     *
     * @return list<string>
     */
    public static function sanitize(mixed $input): array
    {
        if (!is_array($input)) {
            return [];
        }

        $out = [];
        foreach ($input as $value) {
            if (!is_scalar($value)) {
                continue;
            }
            $key = PermissionAliases::canonical(trim((string) $value));
            if ($key !== '' && self::isValid($key) && !in_array($key, $out, true)) {
                $out[] = $key;
            }
            if (count($out) >= self::MAX_KEYS) {
                break;
            }
        }
        return $out;
    }

    /**
     * Read a stored JSON array back as a permission list.
     *
     * Does NOT filter: what is stored is what was granted. It only normalises
     * the old `customers:*` spelling forward (see {@see PermissionAliases}) so
     * a row written before the rename still means the same thing.
     *
     * @return list<string>
     */
    public static function hydrate(mixed $stored): array
    {
        $decoded = is_string($stored) ? json_decode($stored, true) : $stored;
        if (!is_array($decoded)) {
            return [];
        }

        $out = [];
        foreach ($decoded as $value) {
            if (!is_scalar($value)) {
                continue;
            }
            $key = PermissionAliases::canonical((string) $value);
            if ($key !== '' && !in_array($key, $out, true)) {
                $out[] = $key;
            }
        }
        return $out;
    }
}
