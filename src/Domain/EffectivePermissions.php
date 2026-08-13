<?php
declare(strict_types=1);

namespace Tds\AuthApi\Domain;

/**
 * What a user may actually do in one company.
 *
 * ```
 * effective(user, company) = direct grants
 *                          ∪ groups assigned at (user, company)
 *                          ∪ groups assigned globally (company 0)
 *                          ∩ ceiling(user, company)
 * ```
 *
 * ### Grant-only. There are no deny rules, and there will not be
 *
 * Deny rules make an RBAC model unauditable — "why can this person not do X"
 * stops having a single answer — and they interact badly with the ceiling: a
 * deny that the ceiling already covers is dead weight, and one it does not is a
 * second, competing limit.
 *
 * ### The ceiling is intersected here, not only checked on write
 *
 * Checking it only when granting would make it a one-time gate: lower a
 * company's `allowed_permissions` afterwards and every already-assigned group
 * keeps out-granting it. Intersecting at resolve time means a lowered ceiling
 * takes effect on the next token — which is what "ceiling" has to mean to be
 * worth having.
 *
 * A pure function of rows: no PDO, no container. That is what makes the whole
 * rule testable without a database.
 */
final class EffectivePermissions
{
    /**
     * @param list<string> $direct grants stored on the membership
     * @param list<list<string>> $groupPermissionSets one entry per applicable group
     * @param list<string>|null $ceiling null = no ceiling
     * @return list<string>
     */
    public static function resolve(array $direct, array $groupPermissionSets, ?array $ceiling = null): array
    {
        $union = [];
        foreach ([[$direct], $groupPermissionSets] as $source) {
            foreach ($source as $set) {
                foreach ($set as $key) {
                    if (!is_string($key) || $key === '') {
                        continue;
                    }
                    // Normalise the pre-rename spelling forward, so a group
                    // seeded or stored before the rename resolves to the same
                    // right as one written after it.
                    $canonical = PermissionAliases::canonical($key);
                    if (!in_array($canonical, $union, true)) {
                        $union[] = $canonical;
                    }
                }
            }
        }

        if ($ceiling !== null) {
            $allowed = array_map(
                static fn (string $k): string => PermissionAliases::canonical($k),
                $ceiling,
            );
            $union = array_values(array_filter(
                $union,
                static fn (string $key): bool => in_array($key, $allowed, true),
            ));
        }

        // The JWT rides in a cookie; an unbounded array is a header-size limit
        // waiting to be hit. Truncating is the lesser evil versus a token the
        // browser silently refuses to send — and 128 rights in one company is
        // already far past anything the catalog can produce.
        if (count($union) > Permissions::MAX_KEYS) {
            $union = array_slice($union, 0, Permissions::MAX_KEYS);
        }

        return array_values($union);
    }
}
