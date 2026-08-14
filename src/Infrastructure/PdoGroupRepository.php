<?php
declare(strict_types=1);

namespace Tds\AuthApi\Infrastructure;

use PDO;
use Tds\AuthApi\Domain\Group;
use Tds\AuthApi\Domain\Permissions;
use Tds\AuthApi\Service\GroupRepository;

final class PdoGroupRepository implements GroupRepository
{
    private const COLUMNS = 'id, company_id, slug, name, description, permissions, is_system';

    public function __construct(private readonly PDO $pdo)
    {
    }

    public function list(?int $companyId = null): array
    {
        if ($companyId === null) {
            $stmt = $this->pdo->query(
                'SELECT ' . self::COLUMNS . ' FROM auth_group ORDER BY company_id, name'
            );
        } else {
            // Platform groups (0) are assignable everywhere, so a company's
            // view is its own plus those — one query, not two.
            $stmt = $this->pdo->prepare(
                'SELECT ' . self::COLUMNS . ' FROM auth_group
                 WHERE company_id IN (0, :cid) ORDER BY company_id, name'
            );
            $stmt->execute(['cid' => $companyId]);
        }

        return array_map([self::class, 'hydrate'], $stmt->fetchAll(PDO::FETCH_ASSOC));
    }

    public function find(int $id): ?Group
    {
        $stmt = $this->pdo->prepare('SELECT ' . self::COLUMNS . ' FROM auth_group WHERE id = :id LIMIT 1');
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? self::hydrate($row) : null;
    }

    public function create(
        int $companyId,
        string $slug,
        string $name,
        ?string $description,
        array $permissions,
    ): int {
        $stmt = $this->pdo->prepare(
            'INSERT INTO auth_group (company_id, slug, name, description, permissions, is_system)
             VALUES (:cid, :slug, :name, :descr, :perms, 0)'
        );
        $stmt->execute([
            'cid' => $companyId,
            'slug' => $slug,
            'name' => $name,
            'descr' => $description,
            'perms' => json_encode(Permissions::sanitize($permissions)),
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    public function update(int $id, array $fields): void
    {
        $sets = [];
        $params = ['id' => $id];

        if (array_key_exists('name', $fields)) {
            $sets[] = 'name = :name';
            $params['name'] = (string) $fields['name'];
        }
        if (array_key_exists('description', $fields)) {
            $sets[] = 'description = :descr';
            $params['descr'] = $fields['description'] !== null ? (string) $fields['description'] : null;
        }
        if (array_key_exists('permissions', $fields)) {
            $sets[] = 'permissions = :perms';
            $params['perms'] = json_encode(Permissions::sanitize($fields['permissions']));
        }

        if ($sets === []) {
            return;
        }

        $stmt = $this->pdo->prepare(
            'UPDATE auth_group SET ' . implode(', ', $sets) . ', updated_at = NOW() WHERE id = :id'
        );
        $stmt->execute($params);
    }

    public function delete(int $id): bool
    {
        // `auth_user_group.group_id` cascades, so the assignments go with it.
        $stmt = $this->pdo->prepare('DELETE FROM auth_group WHERE id = :id AND is_system = 0');
        $stmt->execute(['id' => $id]);

        return $stmt->rowCount() > 0;
    }

    public function slugExists(string $slug, int $companyId, ?int $exceptId = null): bool
    {
        $sql = 'SELECT id FROM auth_group WHERE slug = :slug AND company_id = :cid';
        $params = ['slug' => $slug, 'cid' => $companyId];
        if ($exceptId !== null) {
            $sql .= ' AND id <> :except';
            $params['except'] = $exceptId;
        }
        $stmt = $this->pdo->prepare($sql . ' LIMIT 1');
        $stmt->execute($params);

        return $stmt->fetch() !== false;
    }

    public function forUserInCompany(int $userId, int $companyId): array
    {
        // Scope 0 is a GLOBAL assignment — the group applies in every company.
        $stmt = $this->pdo->prepare(
            'SELECT ' . implode(', ', array_map(
                static fn (string $c): string => 'g.' . $c,
                explode(', ', self::COLUMNS),
            )) . '
             FROM auth_user_group ug
             JOIN auth_group g ON g.id = ug.group_id
             WHERE ug.user_id = :uid AND ug.company_id IN (0, :cid)'
        );
        $stmt->execute(['uid' => $userId, 'cid' => $companyId]);

        return array_map([self::class, 'hydrate'], $stmt->fetchAll(PDO::FETCH_ASSOC));
    }

    public function assignmentsForUser(int $userId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT company_id, group_id FROM auth_user_group WHERE user_id = :uid ORDER BY company_id, group_id'
        );
        $stmt->execute(['uid' => $userId]);

        $out = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $out[(int) $row['company_id']][] = (int) $row['group_id'];
        }

        return $out;
    }

    public function setForUserInCompany(int $userId, int $companyId, array $groupIds): void
    {
        $ids = array_values(array_unique(array_filter(
            array_map('intval', $groupIds),
            static fn (int $id): bool => $id > 0,
        )));

        $this->pdo->beginTransaction();
        try {
            // Scoped delete: another company's assignments for this user must
            // survive. A company admin only ever reaches their own scope.
            $del = $this->pdo->prepare(
                'DELETE FROM auth_user_group WHERE user_id = :uid AND company_id = :cid'
            );
            $del->execute(['uid' => $userId, 'cid' => $companyId]);

            if ($ids !== []) {
                $ins = $this->pdo->prepare(
                    'INSERT INTO auth_user_group (user_id, group_id, company_id) VALUES (:uid, :gid, :cid)'
                );
                foreach ($ids as $groupId) {
                    $ins->execute(['uid' => $userId, 'gid' => $groupId, 'cid' => $companyId]);
                }
            }

            $this->pdo->commit();
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    public function memberCount(int $groupId): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT COUNT(DISTINCT user_id) AS c FROM auth_user_group WHERE group_id = :gid'
        );
        $stmt->execute(['gid' => $groupId]);

        return (int) ($stmt->fetch(PDO::FETCH_ASSOC)['c'] ?? 0);
    }

    public function memberIds(int $groupId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT DISTINCT user_id FROM auth_user_group WHERE group_id = :gid'
        );
        $stmt->execute(['gid' => $groupId]);

        return array_map('intval', $stmt->fetchAll(PDO::FETCH_COLUMN));
    }

    /** @param array<string,mixed> $row */
    private static function hydrate(array $row): Group
    {
        return new Group(
            id: (int) $row['id'],
            companyId: (int) $row['company_id'],
            slug: (string) $row['slug'],
            name: (string) $row['name'],
            description: $row['description'] !== null ? (string) $row['description'] : null,
            // hydrate(), not sanitize(): what was granted is what is stored.
            permissions: Permissions::hydrate($row['permissions']),
            isSystem: (bool) $row['is_system'],
        );
    }
}
