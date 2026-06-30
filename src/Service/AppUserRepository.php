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
    public function list(?int $customerId = null): array;

    /**
     * @param list<string> $permissions
     * @return int the new user id
     */
    public function create(
        string $email,
        string $passwordHash,
        ?string $name,
        bool $isAdmin,
        ?int $customerId,
        array $permissions,
        string $status = 'active',
    ): int;

    /**
     * Partial update. Recognised keys: email, name, is_admin, customer_id,
     * permissions (list<string>), status. Absent keys are left unchanged.
     *
     * @param array<string,mixed> $fields
     */
    public function update(int $id, array $fields): void;

    public function updatePassword(int $id, string $passwordHash): void;

    public function delete(int $id): bool;

    public function emailExists(string $email, ?int $exceptId = null): bool;
}
