<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Support;

use Tds\AuthApi\Domain\AppUser;
use Tds\AuthApi\Domain\Permissions;
use Tds\AuthApi\Service\AppUserRepository;

/**
 * In-memory AppUserRepository for unit tests that don't need a real DB.
 */
final class FakeAppUserRepository implements AppUserRepository
{
    /** @var array<int, AppUser> */
    public array $users = [];

    private int $nextId = 1;

    public function seed(AppUser $user): void
    {
        $this->users[$user->id] = $user;
        $this->nextId = max($this->nextId, $user->id + 1);
    }

    public function findByEmail(string $email): ?AppUser
    {
        foreach ($this->users as $u) {
            if (strcasecmp($u->email, $email) === 0) {
                return $u;
            }
        }
        return null;
    }

    public function findById(int $id): ?AppUser
    {
        return $this->users[$id] ?? null;
    }

    public function list(?int $customerId = null): array
    {
        $rows = array_values($this->users);
        if ($customerId !== null) {
            $rows = array_values(array_filter($rows, fn (AppUser $u) => $u->customerId === $customerId));
        }
        usort($rows, fn (AppUser $a, AppUser $b) => $b->id <=> $a->id);
        return $rows;
    }

    public function create(
        string $email,
        string $passwordHash,
        ?string $name,
        bool $isAdmin,
        ?int $customerId,
        array $permissions,
        string $status = 'active',
    ): int {
        $id = $this->nextId++;
        $this->users[$id] = new AppUser(
            id: $id,
            email: $email,
            name: $name,
            isAdmin: $isAdmin,
            customerId: $customerId,
            permissions: Permissions::sanitize($permissions),
            status: $status,
            passwordHash: $passwordHash,
        );
        return $id;
    }

    public array $lastUpdateFields = [];

    public function update(int $id, array $fields): void
    {
        $this->lastUpdateFields = $fields;
        $u = $this->users[$id] ?? null;
        if ($u === null) {
            return;
        }
        $this->users[$id] = new AppUser(
            id: $u->id,
            email: array_key_exists('email', $fields) ? (string) $fields['email'] : $u->email,
            name: array_key_exists('name', $fields) ? ($fields['name'] !== null ? (string) $fields['name'] : null) : $u->name,
            isAdmin: array_key_exists('is_admin', $fields) ? (bool) $fields['is_admin'] : $u->isAdmin,
            customerId: array_key_exists('customer_id', $fields) ? ($fields['customer_id'] !== null ? (int) $fields['customer_id'] : null) : $u->customerId,
            permissions: array_key_exists('permissions', $fields) ? Permissions::sanitize($fields['permissions']) : $u->permissions,
            status: array_key_exists('status', $fields) ? (string) $fields['status'] : $u->status,
            passwordHash: $u->passwordHash,
            mustChangePassword: array_key_exists('must_change_password', $fields) ? (bool) $fields['must_change_password'] : $u->mustChangePassword,
            isSupportAgent: array_key_exists('is_support_agent', $fields) ? (bool) $fields['is_support_agent'] : $u->isSupportAgent,
        );
    }

    public function updatePassword(int $id, string $passwordHash): void
    {
        $u = $this->users[$id] ?? null;
        if ($u === null) {
            return;
        }
        $this->users[$id] = new AppUser(
            id: $u->id,
            email: $u->email,
            name: $u->name,
            isAdmin: $u->isAdmin,
            customerId: $u->customerId,
            permissions: $u->permissions,
            status: $u->status,
            passwordHash: $passwordHash,
            mustChangePassword: $u->mustChangePassword,
        );
    }

    public function delete(int $id): bool
    {
        if (!isset($this->users[$id])) {
            return false;
        }
        unset($this->users[$id]);
        return true;
    }

    public function emailExists(string $email, ?int $exceptId = null): bool
    {
        foreach ($this->users as $u) {
            if (strcasecmp($u->email, $email) === 0 && $u->id !== $exceptId) {
                return true;
            }
        }
        return false;
    }
}
