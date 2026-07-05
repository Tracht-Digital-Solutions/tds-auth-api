<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Support;

use Tds\AuthApi\Domain\AppUser;
use Tds\AuthApi\Domain\Membership;
use Tds\AuthApi\Domain\Permissions;
use Tds\AuthApi\Service\AppUserRepository;

/**
 * In-memory AppUserRepository for unit tests that don't need a real DB. Company
 * memberships are kept in `$membershipRows` (keyed by user id) and reattached to
 * the stored AppUser on every mutation, mirroring the PDO repo's behaviour
 * (primary customer_id/permissions synced to the first membership).
 */
final class FakeAppUserRepository implements AppUserRepository
{
    /** @var array<int, AppUser> */
    public array $users = [];

    /** @var array<int, list<array{customerId:int, permissions:list<string>}>> */
    public array $membershipRows = [];

    private int $nextId = 1;

    public function seed(AppUser $user): void
    {
        $this->users[$user->id] = $user;
        $this->nextId = max($this->nextId, $user->id + 1);
        // Backfill membership rows so a seeded single-company user behaves like a
        // real one (companies claim / /me). Explicit memberships win.
        if ($user->memberships !== []) {
            $this->membershipRows[$user->id] = array_map(
                static fn (Membership $m): array => $m->toArray(),
                $user->memberships,
            );
        } elseif ($user->customerId !== null) {
            $this->membershipRows[$user->id] = [
                ['customerId' => $user->customerId, 'permissions' => $user->permissions],
            ];
        }
        $this->users[$user->id] = $this->attach($user);
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
        if ($customerId !== null) {
            $this->membershipRows[$id] = [
                ['customerId' => $customerId, 'permissions' => Permissions::sanitize($permissions)],
            ];
        }
        $this->users[$id] = $this->attach(new AppUser(
            id: $id,
            email: $email,
            name: $name,
            isAdmin: $isAdmin,
            customerId: $customerId,
            permissions: Permissions::sanitize($permissions),
            status: $status,
            passwordHash: $passwordHash,
        ));
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
        $this->users[$id] = $this->attach(new AppUser(
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
        ));
    }

    public function setMemberships(int $userId, array $memberships): void
    {
        $byCustomer = [];
        foreach ($memberships as $m) {
            $cid = (int) ($m['customerId'] ?? 0);
            if ($cid <= 0) {
                continue;
            }
            $byCustomer[$cid] = ['customerId' => $cid, 'permissions' => Permissions::sanitize($m['permissions'] ?? [])];
        }
        $this->membershipRows[$userId] = array_values($byCustomer);

        $u = $this->users[$userId] ?? null;
        if ($u === null) {
            return;
        }
        $primary = $this->membershipRows[$userId][0] ?? null;
        $this->users[$userId] = $this->attach(new AppUser(
            id: $u->id,
            email: $u->email,
            name: $u->name,
            isAdmin: $u->isAdmin,
            customerId: $primary['customerId'] ?? null,
            permissions: $primary['permissions'] ?? [],
            status: $u->status,
            passwordHash: $u->passwordHash,
            mustChangePassword: $u->mustChangePassword,
            isSupportAgent: $u->isSupportAgent,
        ));
    }

    public function updatePassword(int $id, string $passwordHash): void
    {
        $u = $this->users[$id] ?? null;
        if ($u === null) {
            return;
        }
        $this->users[$id] = $this->attach(new AppUser(
            id: $u->id,
            email: $u->email,
            name: $u->name,
            isAdmin: $u->isAdmin,
            customerId: $u->customerId,
            permissions: $u->permissions,
            status: $u->status,
            passwordHash: $passwordHash,
            mustChangePassword: $u->mustChangePassword,
            isSupportAgent: $u->isSupportAgent,
        ));
    }

    public function delete(int $id): bool
    {
        if (!isset($this->users[$id])) {
            return false;
        }
        unset($this->users[$id], $this->membershipRows[$id]);
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

    /** Return a copy of $u with its current membership rows attached. */
    private function attach(AppUser $u): AppUser
    {
        $memberships = array_map(
            static fn (array $r): Membership => new Membership($r['customerId'], $r['permissions']),
            $this->membershipRows[$u->id] ?? [],
        );
        return new AppUser(
            id: $u->id,
            email: $u->email,
            name: $u->name,
            isAdmin: $u->isAdmin,
            customerId: $u->customerId,
            permissions: $u->permissions,
            status: $u->status,
            passwordHash: $u->passwordHash,
            mustChangePassword: $u->mustChangePassword,
            isSupportAgent: $u->isSupportAgent,
            memberships: $memberships,
        );
    }
}
