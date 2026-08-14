<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

use Tds\AuthApi\Domain\CompanyPolicy;
use Tds\AuthApi\Domain\EffectivePermissions;
use Tds\AuthApi\Domain\Group;
use Tds\AuthApi\Domain\Membership;

/**
 * Turns a membership into the permission set that actually applies.
 *
 * The rule itself is a pure function ({@see EffectivePermissions}); this is the
 * thin layer that fetches the rows it needs — the user's groups in that
 * company, and the ceiling from the company policy plus the per-user override.
 *
 * ### Why the JWT carries resolved values, not group ids
 *
 * The `companies` claim keeps its exact shape (`[{id, permissions, admin}]`),
 * so `JwtUserContext` in the composed API and every extension's RBAC check work
 * unchanged — no contract change, no coordinated deploy. Shipping group ids
 * instead would mean every consumer learns what a group is and re-resolves it
 * on every request, against a database it does not have.
 *
 * The cost is that a group edit reaches a user on their next token. That is the
 * same propagation model the rest of this service uses: authorization changes
 * revoke sessions, which forces a fresh token.
 *
 * ### Everything that publishes a membership must come through here
 *
 * This class was registered in the container and injected **nowhere** for its
 * first release: `issueForUser()` was called without a resolver in all four
 * login paths and `MeAction` returned the raw row. The result was a feature
 * that looked complete and did nothing — groups could be created and assigned
 * and granted no rights, and the ceiling was checked when writing but never
 * when resolving, i.e. exactly the one-time gate {@see EffectivePermissions}
 * warns about. If a new code path hands a membership outside this service,
 * route it through {@see self::effective()}.
 */
final class PermissionResolver
{
    public function __construct(
        private readonly GroupRepository $groups,
        private readonly CompanyPolicyRepository $policies,
    ) {
    }

    /**
     * The effective permissions for one membership.
     *
     * @return list<string>
     */
    public function forMembership(int $userId, Membership $membership): array
    {
        $groupSets = array_map(
            static fn (Group $g): array => $g->permissions,
            $this->groups->forUserInCompany($userId, $membership->companyId),
        );

        $ceiling = $this->policies
            ->get($membership->companyId)
            ->ceilingFor($membership->permissionCeiling);

        return EffectivePermissions::resolve(
            $membership->permissions,
            $groupSets,
            $ceiling,
            $membership->permissionDenies,
        );
    }

    /**
     * Does this membership really administer its company?
     *
     * The stored flag alone is not the answer: delegation is a per-company
     * grant, so `is_company_admin = 1` on a company that was never switched on
     * confers nothing. Resolving it here rather than at each reader is what
     * keeps the nav, the token and the middleware from disagreeing.
     */
    public function adminFor(Membership $membership): bool
    {
        return $membership->isCompanyAdmin
            && $this->policies->get($membership->companyId)->allowCompanyAdmins;
    }

    /**
     * The membership as the outside world may believe it: effective
     * permissions, and an admin flag the company policy actually supports.
     */
    public function effective(int $userId, Membership $membership): Membership
    {
        return $membership->resolved(
            $this->forMembership($userId, $membership),
            $this->adminFor($membership),
        );
    }

    /**
     * A callable for {@see JwtService::issueForUser()}.
     *
     * Bound to one user because that is the only shape the issuer needs, and
     * it keeps the resolver from having to guess whose membership it holds.
     *
     * @return callable(Membership): Membership
     */
    public function forUser(int $userId): callable
    {
        return fn (Membership $m): Membership => $this->effective($userId, $m);
    }

    /**
     * The ceiling in force for a membership — what a company admin may grant.
     *
     * @return list<string>|null null = no ceiling
     */
    public function ceilingFor(int $companyId, ?array $userCeiling): ?array
    {
        return $this->policies->get($companyId)->ceilingFor($userCeiling);
    }

    public function policyFor(int $companyId): CompanyPolicy
    {
        return $this->policies->get($companyId);
    }
}
