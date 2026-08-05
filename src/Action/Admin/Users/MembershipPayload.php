<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin\Users;

use Tds\AuthApi\Domain\Permissions;

/**
 * Resolves the company memberships from a user create/update payload. Accepts
 * the new `memberships: [{customerId, permissions}]` shape and falls back to the
 * legacy single-company `customerId` + `permissions` pair. `memberships` wins
 * when both appear. Entries with a non-positive customerId are dropped; unknown
 * permission keys are sanitised out.
 */
final class MembershipPayload
{
    /**
     * @param array<string,mixed> $body
     * @return list<array{customerId:int, permissions:list<string>}>
     */
    public static function resolve(array $body): array
    {
        if (array_key_exists('memberships', $body) && is_array($body['memberships'])) {
            $out = [];
            foreach ($body['memberships'] as $m) {
                if (!is_array($m)) {
                    continue;
                }
                $cid = (int) ($m['customerId'] ?? 0);
                if ($cid <= 0) {
                    continue;
                }
                $out[] = [
                    'customerId' => $cid,
                    'permissions' => Permissions::sanitize($m['permissions'] ?? []),
                ];
            }
            return $out;
        }

        // Legacy single-company fallback.
        $cid = null;
        if (isset($body['customerId']) && $body['customerId'] !== null && $body['customerId'] !== '') {
            $cid = (int) $body['customerId'];
        }
        if ($cid === null || $cid <= 0) {
            return [];
        }
        return [[
            'customerId' => $cid,
            'permissions' => Permissions::sanitize($body['permissions'] ?? []),
        ]];
    }

    /**
     * Whether the payload carries any company assignment at all (so update can
     * tell "no membership keys present" from "explicitly cleared to none").
     *
     * @param array<string,mixed> $body
     */
    public static function present(array $body): bool
    {
        return array_key_exists('memberships', $body)
            || array_key_exists('customerId', $body)
            || array_key_exists('permissions', $body);
    }
}
