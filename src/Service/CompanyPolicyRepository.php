<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

use Tds\AuthApi\Domain\CompanyPolicy;

interface CompanyPolicyRepository
{
    /**
     * The company's policy, or the unrestricted default when none is stored.
     *
     * Never returns null: "no policy" is a real, permissive state, and making
     * every caller handle a null would be an invitation to forget one and skip
     * the check entirely.
     */
    public function get(int $companyId): CompanyPolicy;

    /** @return list<CompanyPolicy> only companies that actually have a policy */
    public function all(): array;

    /**
     * Upsert. `$fields` recognises maxUsers, allowedPermissions,
     * allowCustomGroups; absent keys keep their current value.
     *
     * @param array<string,mixed> $fields
     */
    public function save(int $companyId, array $fields): CompanyPolicy;

    /**
     * Seats in use — every membership of the company, **including disabled
     * users**.
     *
     * Counting only active accounts would make "disable, then add another"
     * a free extra seat, which is the first thing anyone tries.
     */
    public function seatsUsed(int $companyId): int;

    /**
     * Reserve a seat for a new membership, or fail.
     *
     * Must run the count and the insert under one lock: two concurrent creates
     * both pass a plain check-then-insert. Returns false when the cap is
     * reached; the caller turns that into a 409.
     *
     * @param callable():void $insert the write to perform while holding the lock
     */
    public function withSeat(int $companyId, callable $insert): bool;
}
