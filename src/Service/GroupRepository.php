<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

use Tds\AuthApi\Domain\Group;

interface GroupRepository
{
    /**
     * Groups visible in one scope: the platform groups plus that company's own.
     * `$companyId = null` lists everything (platform admin view).
     *
     * @return list<Group>
     */
    public function list(?int $companyId = null): array;

    public function find(int $id): ?Group;

    /** @param list<string> $permissions */
    public function create(
        int $companyId,
        string $slug,
        string $name,
        ?string $description,
        array $permissions,
    ): int;

    /**
     * Partial update. Recognised keys: name, description, permissions.
     * `slug`, `company_id` and `is_system` are deliberately NOT updatable —
     * other rows reference a group by slug, and moving one between companies
     * would silently change who it grants.
     *
     * @param array<string,mixed> $fields
     */
    public function update(int $id, array $fields): void;

    public function delete(int $id): bool;

    public function slugExists(string $slug, int $companyId, ?int $exceptId = null): bool;

    /**
     * The groups that apply to $userId inside $companyId — that company's
     * assignments plus the global ones (scope 0).
     *
     * @return list<Group>
     */
    public function forUserInCompany(int $userId, int $companyId): array;

    /**
     * Assigned group ids per company for one user, as `companyId => [ids]`.
     * Used to render the editor without N queries.
     *
     * @return array<int, list<int>>
     */
    public function assignmentsForUser(int $userId): array;

    /**
     * Replace the user's group assignments **within one company**, leaving
     * every other company's untouched.
     *
     * Scoped on purpose: the platform user editor saves one membership at a
     * time, and a company admin must never be able to reach another company's
     * assignments.
     *
     * @param list<int> $groupIds
     */
    public function setForUserInCompany(int $userId, int $companyId, array $groupIds): void;

    /** How many users are assigned to a group — the "in use" warning in the UI. */
    public function memberCount(int $groupId): int;

    /**
     * The user ids assigned to a group, in any scope.
     *
     * Editing a group's permissions has to revoke its members' sessions — the
     * set rides in a signed token, so without that the change reaches nobody
     * until their hour is up.
     *
     * @return list<int>
     */
    public function memberIds(int $groupId): array;
}
