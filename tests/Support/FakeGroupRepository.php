<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Support;

use Tds\AuthApi\Domain\Group;
use Tds\AuthApi\Service\GroupRepository;

/**
 * In-memory groups and assignments.
 *
 * Models the one property the resolution rule depends on: an assignment is
 * scoped to a company, and **scope 0 is global** — it applies inside every
 * company. A fake that ignored that would let `forUserInCompany()` pass while
 * the real query returns a different set.
 */
final class FakeGroupRepository implements GroupRepository
{
    /** @var array<int, Group> */
    private array $groups = [];

    /** @var array<int, array<int, list<int>>> userId => companyId => groupIds */
    private array $assignments = [];

    private int $nextId = 1;

    public function list(?int $companyId = null): array
    {
        return array_values(array_filter(
            $this->groups,
            static fn (Group $g): bool => $companyId === null || $g->assignableIn($companyId),
        ));
    }

    public function find(int $id): ?Group
    {
        return $this->groups[$id] ?? null;
    }

    public function create(
        int $companyId,
        string $slug,
        string $name,
        ?string $description,
        array $permissions,
    ): int {
        $id = $this->nextId++;
        $this->groups[$id] = new Group($id, $companyId, $slug, $name, $description, array_values($permissions));

        return $id;
    }

    public function update(int $id, array $fields): void
    {
        $g = $this->groups[$id] ?? null;
        if ($g === null) {
            return;
        }
        $this->groups[$id] = new Group(
            $g->id,
            $g->companyId,
            $g->slug,
            (string) ($fields['name'] ?? $g->name),
            array_key_exists('description', $fields) ? $fields['description'] : $g->description,
            array_values((array) ($fields['permissions'] ?? $g->permissions)),
            $g->isSystem,
        );
    }

    public function delete(int $id): bool
    {
        if (!isset($this->groups[$id])) {
            return false;
        }
        unset($this->groups[$id]);

        return true;
    }

    public function slugExists(string $slug, int $companyId, ?int $exceptId = null): bool
    {
        foreach ($this->groups as $g) {
            if ($g->slug === $slug && $g->companyId === $companyId && $g->id !== $exceptId) {
                return true;
            }
        }

        return false;
    }

    public function forUserInCompany(int $userId, int $companyId): array
    {
        $ids = array_merge(
            $this->assignments[$userId][$companyId] ?? [],
            // Scope 0 is global: it applies inside this company too.
            $this->assignments[$userId][0] ?? [],
        );

        $out = [];
        foreach (array_unique($ids) as $id) {
            $group = $this->groups[$id] ?? null;
            if ($group !== null) {
                $out[] = $group;
            }
        }

        return $out;
    }

    public function assignmentsForUser(int $userId): array
    {
        return $this->assignments[$userId] ?? [];
    }

    public function setForUserInCompany(int $userId, int $companyId, array $groupIds): void
    {
        $this->assignments[$userId][$companyId] = array_values(array_unique(array_map('intval', $groupIds)));
    }

    public function memberCount(int $groupId): int
    {
        return count($this->memberIds($groupId));
    }

    public function memberIds(int $groupId): array
    {
        $out = [];
        foreach ($this->assignments as $userId => $byCompany) {
            foreach ($byCompany as $ids) {
                if (in_array($groupId, $ids, true) && !in_array($userId, $out, true)) {
                    $out[] = $userId;
                }
            }
        }

        return $out;
    }

    // --- test helpers -----------------------------------------------------

    public function add(Group $group): void
    {
        $this->groups[$group->id] = $group;
        $this->nextId = max($this->nextId, $group->id + 1);
    }

    /** Assign a group to a user inside one company (0 = every company). */
    public function assign(int $userId, int $companyId, int $groupId): void
    {
        $existing = $this->assignments[$userId][$companyId] ?? [];
        $existing[] = $groupId;
        $this->assignments[$userId][$companyId] = array_values(array_unique($existing));
    }
}
