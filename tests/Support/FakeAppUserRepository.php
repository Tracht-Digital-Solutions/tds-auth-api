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
        } elseif ($user->companyId !== null) {
            $this->membershipRows[$user->id] = [
                ['companyId' => $user->companyId, 'permissions' => $user->permissions],
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

    public function list(?int $companyId = null): array
    {
        $rows = array_values($this->users);
        if ($companyId !== null) {
            // Mirrors the PDO repo's JOIN: a user counts as being in a company
            // when they hold a MEMBERSHIP of it, not when it happens to be
            // their denormalised primary.
            $rows = array_values(array_filter($rows, function (AppUser $u) use ($companyId): bool {
                foreach ($this->membershipRows[$u->id] ?? [] as $row) {
                    if (($row['companyId'] ?? null) === $companyId) {
                        return true;
                    }
                }
                return false;
            }));
        }
        usort($rows, fn (AppUser $a, AppUser $b) => $b->id <=> $a->id);
        return $rows;
    }

    public function create(
        string $email,
        string $passwordHash,
        ?string $name,
        bool $isAdmin,
        ?int $companyId,
        array $permissions,
        string $status = 'active',
    ): int {
        $id = $this->nextId++;
        if ($companyId !== null) {
            $this->membershipRows[$id] = [
                ['companyId' => $companyId, 'permissions' => Permissions::sanitize($permissions)],
            ];
        }
        $this->users[$id] = $this->attach(new AppUser(
            id: $id,
            email: $email,
            name: $name,
            isAdmin: $isAdmin,
            companyId: $companyId,
            permissions: Permissions::sanitize($permissions),
            status: $status,
            passwordHash: $passwordHash,
        ));
        return $id;
    }

    public array $lastUpdateFields = [];

    /**
     * Every update() call, keyed by user id and merged — so a test can assert
     * what was written for ONE user without depending on call order, which is
     * what `lastUpdateFields` alone forces.
     *
     * @var array<int, array<string,mixed>>
     */
    public array $updates = [];

    public function update(int $id, array $fields): void
    {
        $this->lastUpdateFields = $fields;
        $this->updates[$id] = array_merge($this->updates[$id] ?? [], $fields);
        $u = $this->users[$id] ?? null;
        if ($u === null) {
            return;
        }
        $nullable = static fn (mixed $v): ?string => $v !== null ? (string) $v : null;
        $this->users[$id] = $this->attach(new AppUser(
            id: $u->id,
            email: array_key_exists('email', $fields) ? (string) $fields['email'] : $u->email,
            name: array_key_exists('name', $fields) ? $nullable($fields['name']) : $u->name,
            isAdmin: array_key_exists('is_admin', $fields) ? (bool) $fields['is_admin'] : $u->isAdmin,
            companyId: array_key_exists('company_id', $fields) ? ($fields['company_id'] !== null ? (int) $fields['company_id'] : null) : $u->companyId,
            permissions: array_key_exists('permissions', $fields) ? Permissions::sanitize($fields['permissions']) : $u->permissions,
            status: array_key_exists('status', $fields) ? (string) $fields['status'] : $u->status,
            passwordHash: $u->passwordHash,
            mustChangePassword: array_key_exists('must_change_password', $fields) ? (bool) $fields['must_change_password'] : $u->mustChangePassword,
            isSupportAgent: array_key_exists('is_support_agent', $fields) ? (bool) $fields['is_support_agent'] : $u->isSupportAgent,
            isBlogAuthor: array_key_exists('is_blog_author', $fields) ? (bool) $fields['is_blog_author'] : $u->isBlogAuthor,
            avatarUrl: array_key_exists('avatar_url', $fields) ? $nullable($fields['avatar_url']) : $u->avatarUrl,
            bio: array_key_exists('bio', $fields) ? $nullable($fields['bio']) : $u->bio,
            displayName: array_key_exists('display_name', $fields) ? $nullable($fields['display_name']) : $u->displayName,
        ));
    }

    public function setMemberships(int $userId, array $memberships): void
    {
        $byCompany = [];
        foreach ($memberships as $m) {
            $cid = (int) ($m['companyId'] ?? $m['customerId'] ?? 0);
            if ($cid <= 0) {
                continue;
            }
            $byCompany[$cid] = [
                'companyId' => $cid,
                'permissions' => Permissions::sanitize($m['permissions'] ?? []),
                'isCompanyAdmin' => (bool) ($m['isCompanyAdmin'] ?? false),
                'groupIds' => array_map('intval', (array) ($m['groupIds'] ?? [])),
                'permissionCeiling' => array_key_exists('permissionCeiling', $m) && $m['permissionCeiling'] !== null
                    ? Permissions::sanitize($m['permissionCeiling'])
                    : null,
            ];
        }
        $this->membershipRows[$userId] = array_values($byCompany);

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
            companyId: $primary['companyId'] ?? null,
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
            companyId: $u->companyId,
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

    public function setCompanyMembership(
        int $userId,
        int $companyId,
        array $permissions,
        bool $isCompanyAdmin,
        ?array $permissionCeiling = null,
        bool $updateCeiling = false,
    ): void {
        // Single-row upsert: the user's OTHER companies survive. That is the
        // property the company-scoped routes depend on, so the fake has to
        // model it rather than replacing the whole set.
        $rows = $this->membershipRows[$userId] ?? [];
        $found = false;
        foreach ($rows as $i => $row) {
            if (($row['companyId'] ?? null) === $companyId) {
                $rows[$i]['permissions'] = Permissions::sanitize($permissions);
                $rows[$i]['isCompanyAdmin'] = $isCompanyAdmin;
                if ($updateCeiling) {
                    $rows[$i]['permissionCeiling'] = $permissionCeiling;
                }
                $found = true;
                break;
            }
        }
        if (!$found) {
            $rows[] = [
                'companyId' => $companyId,
                'permissions' => Permissions::sanitize($permissions),
                'isCompanyAdmin' => $isCompanyAdmin,
                'groupIds' => [],
                'permissionCeiling' => $updateCeiling ? $permissionCeiling : null,
            ];
        }
        $this->membershipRows[$userId] = array_values($rows);

        if (isset($this->users[$userId])) {
            $this->users[$userId] = $this->attach($this->users[$userId]);
        }
    }

    public function removeCompanyMembership(int $userId, int $companyId): bool
    {
        $before = count($this->membershipRows[$userId] ?? []);
        $this->membershipRows[$userId] = array_values(array_filter(
            $this->membershipRows[$userId] ?? [],
            static fn (array $r): bool => ($r['companyId'] ?? null) !== $companyId,
        ));

        if (isset($this->users[$userId])) {
            $this->users[$userId] = $this->attach($this->users[$userId]);
        }

        return $before !== count($this->membershipRows[$userId]);
    }

    public function companyAdminCount(int $companyId): int
    {
        $count = 0;
        foreach ($this->membershipRows as $rows) {
            foreach ($rows as $row) {
                if (($row['companyId'] ?? null) === $companyId && ($row['isCompanyAdmin'] ?? false)) {
                    $count++;
                }
            }
        }

        return $count;
    }

    /** Return a copy of $u with its current membership rows attached. */
    private function attach(AppUser $u): AppUser
    {
        $memberships = array_map(
            static fn (array $r): Membership => new Membership(
                $r['companyId'],
                $r['permissions'],
                (bool) ($r['isCompanyAdmin'] ?? false),
                array_map('intval', (array) ($r['groupIds'] ?? [])),
                $r['permissionCeiling'] ?? null,
            ),
            $this->membershipRows[$u->id] ?? [],
        );
        return new AppUser(
            id: $u->id,
            email: $u->email,
            name: $u->name,
            isAdmin: $u->isAdmin,
            companyId: $u->companyId,
            permissions: $u->permissions,
            status: $u->status,
            passwordHash: $u->passwordHash,
            mustChangePassword: $u->mustChangePassword,
            isSupportAgent: $u->isSupportAgent,
            isBlogAuthor: $u->isBlogAuthor,
            avatarUrl: $u->avatarUrl,
            bio: $u->bio,
            memberships: $memberships,
            displayName: $u->displayName,
        );
    }
}
