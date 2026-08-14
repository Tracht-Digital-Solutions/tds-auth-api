<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Support;

use Tds\AuthApi\Domain\CompanyPolicy;
use Tds\AuthApi\Service\CompanyPolicyRepository;

/**
 * In-memory company policies.
 *
 * The default matters: an unconfigured company is `CompanyPolicy::unrestricted()`,
 * which has **no seat cap, no ceiling and no delegation**. A test that wants a
 * company admin to get anywhere has to switch delegation on, exactly as a
 * platform admin does — so forgetting it in production shows up here first.
 */
final class FakeCompanyPolicyRepository implements CompanyPolicyRepository
{
    /** @var array<int, CompanyPolicy> */
    private array $policies = [];

    /** @var array<int, int> */
    private array $seats = [];

    public function get(int $companyId): CompanyPolicy
    {
        return $this->policies[$companyId] ?? CompanyPolicy::unrestricted($companyId);
    }

    public function all(): array
    {
        return array_values($this->policies);
    }

    public function save(int $companyId, array $fields): CompanyPolicy
    {
        $current = $this->get($companyId);

        $allowed = $current->allowedPermissions;
        if (array_key_exists('allowedPermissions', $fields)) {
            // null (no ceiling) and [] (grant nothing) stay distinct here too —
            // a fake that collapses them hides the bug it exists to catch.
            $allowed = $fields['allowedPermissions'] === null
                ? null
                : array_values((array) $fields['allowedPermissions']);
        }

        $policy = new CompanyPolicy(
            companyId: $companyId,
            maxUsers: array_key_exists('maxUsers', $fields)
                ? ($fields['maxUsers'] !== null ? (int) $fields['maxUsers'] : null)
                : $current->maxUsers,
            allowedPermissions: $allowed,
            allowCustomGroups: array_key_exists('allowCustomGroups', $fields)
                ? (bool) $fields['allowCustomGroups']
                : $current->allowCustomGroups,
            allowCompanyAdmins: array_key_exists('allowCompanyAdmins', $fields)
                ? (bool) $fields['allowCompanyAdmins']
                : $current->allowCompanyAdmins,
        );

        $this->policies[$companyId] = $policy;

        return $policy;
    }

    public function seatsUsed(int $companyId): int
    {
        return $this->seats[$companyId] ?? 0;
    }

    public function withSeat(int $companyId, callable $insert): bool
    {
        $max = $this->get($companyId)->maxUsers;
        if ($max !== null && $this->seatsUsed($companyId) >= $max) {
            return false;
        }

        $insert();
        $this->seats[$companyId] = $this->seatsUsed($companyId) + 1;

        return true;
    }

    // --- test helpers -----------------------------------------------------

    public function set(CompanyPolicy $policy): void
    {
        $this->policies[$policy->companyId] = $policy;
    }

    /** The shorthand almost every company-admin test needs. */
    public function allowDelegation(int $companyId, bool $allow = true): void
    {
        $this->save($companyId, ['allowCompanyAdmins' => $allow]);
    }

    public function setSeatsUsed(int $companyId, int $used): void
    {
        $this->seats[$companyId] = $used;
    }
}
