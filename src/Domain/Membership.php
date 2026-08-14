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
 * `(direct ∪ groups) \ denies ∩ ceiling` — see {@see EffectivePermissions},
 * which is what the JWT carries.
 *
 * ### `permissionCeiling` and `permissionDenies` are not the same thing
 *
 * The ceiling is the **platform admin's limit on delegation**: the most this
 * person may ever be granted, which a company admin cannot raise. The denies
 * are the **current decision** about this person, editable by whoever manages
 * them. A right can be inside the ceiling and still denied; a right cannot be
 * outside the ceiling and granted. Conflating them is the easy mistake here.
 */
final class Membership
{
    /**
     * @param list<string> $permissions direct grants (not the effective set)
     * @param list<int> $groupIds groups assigned to this user IN this company
     * @param list<string>|null $permissionCeiling per-user cap; null = inherit
     *                                             the company policy
     * @param list<string> $permissionDenies withheld from this person, even
     *                                       when a group grants it
     */
    public function __construct(
        public readonly int $companyId,
        public readonly array $permissions,
        public readonly bool $isCompanyAdmin = false,
        public readonly array $groupIds = [],
        public readonly ?array $permissionCeiling = null,
        public readonly array $permissionDenies = [],
    ) {
    }

    /**
     * A copy with the resolved values — what the caller may actually believe.
     *
     * `$permissions` becomes the EFFECTIVE set and `$isCompanyAdmin` is folded
     * against the company's delegation flag. Everything that hands a membership
     * to the outside world ({@see \Tds\AuthApi\Service\JwtService},
     * `MeAction`) goes through {@see \Tds\AuthApi\Service\PermissionResolver}
     * to get one of these, so the raw row never leaves the service claiming
     * more than it is worth.
     *
     * @param list<string> $permissions
     */
    public function resolved(array $permissions, bool $isCompanyAdmin): self
    {
        return new self(
            $this->companyId,
            $permissions,
            $isCompanyAdmin,
            $this->groupIds,
            $this->permissionCeiling,
            $this->permissionDenies,
        );
    }

    /**
     * @return array{
     *   companyId:int, customerId:int, permissions:list<string>,
     *   isCompanyAdmin:bool, groupIds:list<int>,
     *   permissionCeiling:list<string>|null, permissionDenies:list<string>
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
            'permissionDenies' => $this->permissionDenies,
        ];
    }
}
