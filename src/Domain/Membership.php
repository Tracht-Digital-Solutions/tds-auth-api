<?php
declare(strict_types=1);

namespace Tds\AuthApi\Domain;

/**
 * One company membership of a login: the company (Firma) the account can
 * access, what it may do there, and whether it administers that company.
 *
 * A login carries a list of these — belonging to several companies with a
 * different role in each is the normal case, not an edge case. The portal shows
 * one active company at a time.
 *
 * `$permissions` are the **direct** grants. The set that actually applies is
 * `direct ∪ groups ∩ ceiling` — see {@see EffectivePermissions}, which is what
 * the JWT carries.
 */
final class Membership
{
    /**
     * @param list<string> $permissions direct grants (not the effective set)
     * @param list<int> $groupIds groups assigned to this user IN this company
     * @param list<string>|null $permissionCeiling per-user cap; null = inherit
     *                                             the company policy
     */
    public function __construct(
        public readonly int $companyId,
        public readonly array $permissions,
        public readonly bool $isCompanyAdmin = false,
        public readonly array $groupIds = [],
        public readonly ?array $permissionCeiling = null,
    ) {
    }

    /**
     * @return array{
     *   companyId:int, customerId:int, permissions:list<string>,
     *   isCompanyAdmin:bool, groupIds:list<int>, permissionCeiling:list<string>|null
     * }
     */
    public function toArray(): array
    {
        return [
            'companyId' => $this->companyId,
            // Deprecated alias, emitted for one release so a client built
            // against the old name keeps rendering. Dropped in the follow-up.
            'customerId' => $this->companyId,
            'permissions' => $this->permissions,
            'isCompanyAdmin' => $this->isCompanyAdmin,
            'groupIds' => $this->groupIds,
            'permissionCeiling' => $this->permissionCeiling,
        ];
    }
}
