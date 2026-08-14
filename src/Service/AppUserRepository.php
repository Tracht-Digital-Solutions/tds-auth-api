<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

use Tds\AuthApi\Domain\AppUser;

interface AppUserRepository
{
    public function findByEmail(string $email): ?AppUser;

    public function findById(int $id): ?AppUser;

    /**
     * List users, newest first. Optionally filter to one company.
     *
     * @return list<AppUser>
     */
    public function list(?int $companyId = null): array;

    /**
     * @param list<string> $permissions
     * @return int the new user id
     */
    public function create(
        string $email,
        string $passwordHash,
        ?string $name,
        bool $isAdmin,
        ?int $companyId,
        array $permissions,
        string $status = 'active',
    ): int;

    /**
     * Partial update. Recognised keys: email, name, display_name, is_admin,
     * is_support_agent, is_blog_author, avatar_url, bio, company_id,
     * permissions (list<string>), status, must_change_password. Absent keys are
     * left unchanged.
     *
     * @param array<string,mixed> $fields
     */
    public function update(int $id, array $fields): void;

    public function updatePassword(int $id, string $passwordHash): void;

    public function delete(int $id): bool;

    public function emailExists(string $email, ?int $exceptId = null): bool;

    /**
     * Replace a user's FULL set of company memberships, and sync the
     * denormalised `app_user.company_id` / `permissions` columns to the primary
     * (first) membership — or NULL / [] when the list is empty.
     *
     * **Platform-admin surface only.** A company-scoped caller must use
     * {@see self::setCompanyMembership()}: this one replaces everything, so
     * reached from `/company/*` it would let one company's admin drop a user's
     * membership of another company with a payload that never mentioned it.
     *
     * @param list<array{
     *   companyId?:int, customerId?:int, permissions:list<string>,
     *   isCompanyAdmin?:bool, permissionCeiling?:list<string>|null,
     *   permissionDenies?:list<string>
     * }> $memberships
     */
    public function setMemberships(int $userId, array $memberships): void;

    /**
     * Upsert ONE membership, leaving the user's other companies untouched.
     * The only membership write reachable from a company-scoped route.
     *
     * `$permissionCeiling` is applied only when `$updateCeiling` is true, so a
     * company admin (who may not set ceilings) cannot clear one by omitting it.
     *
     * @param list<string> $permissions
     * @param list<string>|null $permissionCeiling
     */
    public function setCompanyMembership(
        int $userId,
        int $companyId,
        array $permissions,
        bool $isCompanyAdmin,
        ?array $permissionCeiling = null,
        bool $updateCeiling = false,
        array $permissionDenies = [],
    ): void;

    /** Remove one membership. Never deletes the `app_user` row. */
    public function removeCompanyMembership(int $userId, int $companyId): bool;

    /** How many company admins a company has — the last-admin guard. */
    public function companyAdminCount(int $companyId): int;
}
