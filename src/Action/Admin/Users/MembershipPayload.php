<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin\Users;

use Tds\AuthApi\Domain\Permissions;

/**
 * Resolves the company memberships from a user create/update payload.
 *
 * Accepts `memberships: [{companyId, permissions, groupIds, isCompanyAdmin,
 * permissionCeiling, permissionDenies}]` and falls back to the legacy single-company
 * `companyId` + `permissions` pair; `memberships` wins when both appear.
 * `customerId` is still read as an alias of `companyId` for one release.
 *
 * Entries with a non-positive company id are dropped, and permission keys are
 * validated by shape (see {@see Permissions::sanitize()}).
 */
final class MembershipPayload
{
    /**
     * @param array<string,mixed> $body
     * @return list<array{
     *   companyId:int, permissions:list<string>, groupIds:list<int>,
     *   isCompanyAdmin:bool, permissionCeiling:list<string>|null,
     *   permissionDenies:list<string>
     * }>
     */
    public static function resolve(array $body): array
    {
        if (array_key_exists('memberships', $body) && is_array($body['memberships'])) {
            $out = [];
            foreach ($body['memberships'] as $m) {
                if (!is_array($m)) {
                    continue;
                }
                $cid = (int) ($m['companyId'] ?? $m['customerId'] ?? 0);
                if ($cid <= 0) {
                    continue;
                }
                $out[] = [
                    'companyId' => $cid,
                    'permissions' => Permissions::sanitize($m['permissions'] ?? []),
                    'groupIds' => self::ids($m['groupIds'] ?? []),
                    'isCompanyAdmin' => (bool) ($m['isCompanyAdmin'] ?? false),
                    // Absent and null are both "no per-user ceiling"; an empty
                    // array is the different, deliberate "may hold nothing".
                    'permissionCeiling' => array_key_exists('permissionCeiling', $m)
                        && $m['permissionCeiling'] !== null
                        ? Permissions::sanitize($m['permissionCeiling'])
                        : null,
                    // Unlike the ceiling, absent and empty are the same thing —
                    // there is no third state a deny list can be in.
                    'permissionDenies' => Permissions::sanitize($m['permissionDenies'] ?? []),
                ];
            }
            return $out;
        }

        // Legacy single-company fallback.
        $raw = $body['companyId'] ?? $body['customerId'] ?? null;
        if ($raw === null || $raw === '') {
            return [];
        }
        $cid = (int) $raw;
        if ($cid <= 0) {
            return [];
        }

        return [[
            'companyId' => $cid,
            'permissions' => Permissions::sanitize($body['permissions'] ?? []),
            'groupIds' => [],
            'isCompanyAdmin' => false,
            'permissionCeiling' => null,
            'permissionDenies' => [],
        ]];
    }

    /**
     * Whether the payload carries a company assignment at all — how an update
     * tells "said nothing about memberships" from "explicitly cleared to none".
     *
     * **`permissions` alone does NOT count**, and that is the fix for a real
     * data-loss bug: it used to, so a body carrying only `permissions` made
     * this return true while {@see self::resolve()} returned `[]` — and the
     * caller dutifully replaced every membership with nothing. A payload that
     * never mentions a company must not be able to remove the user from all of
     * them.
     *
     * @param array<string,mixed> $body
     */
    public static function present(array $body): bool
    {
        return array_key_exists('memberships', $body)
            || array_key_exists('companyId', $body)
            || array_key_exists('customerId', $body);
    }

    /**
     * @param mixed $raw
     * @return list<int>
     */
    private static function ids(mixed $raw): array
    {
        if (!is_array($raw)) {
            return [];
        }
        $out = [];
        foreach ($raw as $value) {
            $id = (int) $value;
            if ($id > 0 && !in_array($id, $out, true)) {
                $out[] = $id;
            }
        }
        return $out;
    }
}
