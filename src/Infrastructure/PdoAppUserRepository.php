<?php
declare(strict_types=1);

namespace Tds\AuthApi\Infrastructure;

use PDO;
use Tds\AuthApi\Domain\AppUser;
use Tds\AuthApi\Domain\Membership;
use Tds\AuthApi\Domain\Permissions;
use Tds\AuthApi\Service\AppUserRepository;

final class PdoAppUserRepository implements AppUserRepository
{
    private const COLUMNS = 'id, email, password_hash, name, avatar_url, bio, is_admin, is_support_agent, is_blog_author, customer_id, permissions, status, must_change_password';

    public function __construct(private readonly PDO $pdo)
    {
    }

    public function findByEmail(string $email): ?AppUser
    {
        $stmt = $this->pdo->prepare(
            'SELECT ' . self::COLUMNS . ' FROM app_user WHERE email = :email LIMIT 1'
        );
        $stmt->execute(['email' => $email]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $this->hydrate($row) : null;
    }

    public function findById(int $id): ?AppUser
    {
        $stmt = $this->pdo->prepare(
            'SELECT ' . self::COLUMNS . ' FROM app_user WHERE id = :id LIMIT 1'
        );
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $this->hydrate($row) : null;
    }

    public function list(?int $customerId = null): array
    {
        if ($customerId !== null) {
            $stmt = $this->pdo->prepare(
                'SELECT ' . self::COLUMNS . ' FROM app_user WHERE customer_id = :cid ORDER BY id DESC'
            );
            $stmt->execute(['cid' => $customerId]);
        } else {
            $stmt = $this->pdo->query('SELECT ' . self::COLUMNS . ' FROM app_user ORDER BY id DESC');
        }
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        return array_map(fn (array $r) => $this->hydrate($r), $rows);
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
        $perms = Permissions::sanitize($permissions);
        $stmt = $this->pdo->prepare(
            'INSERT INTO app_user (email, password_hash, name, is_admin, customer_id, permissions, status, created_at, updated_at) '
            . 'VALUES (:email, :hash, :name, :admin, :cid, :perms, :status, NOW(), NOW())'
        );
        $stmt->execute([
            'email' => $email,
            'hash' => $passwordHash,
            'name' => $name,
            'admin' => $isAdmin ? 1 : 0,
            'cid' => $customerId,
            'perms' => json_encode($perms),
            'status' => $status,
        ]);
        $id = (int) $this->pdo->lastInsertId();

        // Mirror the primary company as a membership row so the many-to-many is
        // the single source of truth from creation onward.
        if ($customerId !== null) {
            $ins = $this->pdo->prepare(
                'INSERT INTO app_user_customer (user_id, customer_id, permissions, created_at) '
                . 'VALUES (:uid, :cid, :perms, NOW())'
            );
            $ins->execute(['uid' => $id, 'cid' => $customerId, 'perms' => json_encode($perms)]);
        }
        return $id;
    }

    public function setMemberships(int $userId, array $memberships): void
    {
        // Normalise + de-dupe by customer_id (last wins), preserving order.
        $byCustomer = [];
        foreach ($memberships as $m) {
            $cid = (int) ($m['customerId'] ?? 0);
            if ($cid <= 0) {
                continue;
            }
            $byCustomer[$cid] = Permissions::sanitize($m['permissions'] ?? []);
        }

        $this->pdo->beginTransaction();
        try {
            $del = $this->pdo->prepare('DELETE FROM app_user_customer WHERE user_id = :uid');
            $del->execute(['uid' => $userId]);

            $ins = $this->pdo->prepare(
                'INSERT INTO app_user_customer (user_id, customer_id, permissions, created_at) '
                . 'VALUES (:uid, :cid, :perms, NOW())'
            );
            foreach ($byCustomer as $cid => $perms) {
                $ins->execute(['uid' => $userId, 'cid' => $cid, 'perms' => json_encode($perms)]);
            }

            // Sync the legacy primary columns to the first membership.
            $primaryCid = null;
            $primaryPerms = [];
            foreach ($byCustomer as $cid => $perms) {
                $primaryCid = $cid;
                $primaryPerms = $perms;
                break;
            }
            $sync = $this->pdo->prepare(
                'UPDATE app_user SET customer_id = :cid, permissions = :perms, updated_at = NOW() WHERE id = :uid'
            );
            $sync->execute([
                'uid' => $userId,
                'cid' => $primaryCid,
                'perms' => json_encode($primaryPerms),
            ]);

            $this->pdo->commit();
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /** @return list<Membership> */
    private function membershipsForUser(int $userId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT customer_id, permissions FROM app_user_customer WHERE user_id = :uid ORDER BY id ASC'
        );
        $stmt->execute(['uid' => $userId]);
        $out = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $decoded = json_decode((string) ($row['permissions'] ?? '[]'), true);
            $out[] = new Membership(
                customerId: (int) $row['customer_id'],
                permissions: Permissions::sanitize(is_array($decoded) ? $decoded : []),
            );
        }
        return $out;
    }

    public function update(int $id, array $fields): void
    {
        $sets = [];
        $params = ['id' => $id];

        if (array_key_exists('email', $fields)) {
            $sets[] = 'email = :email';
            $params['email'] = (string) $fields['email'];
        }
        if (array_key_exists('name', $fields)) {
            $sets[] = 'name = :name';
            $params['name'] = $fields['name'] !== null ? (string) $fields['name'] : null;
        }
        if (array_key_exists('is_admin', $fields)) {
            $sets[] = 'is_admin = :admin';
            $params['admin'] = $fields['is_admin'] ? 1 : 0;
        }
        if (array_key_exists('is_support_agent', $fields)) {
            $sets[] = 'is_support_agent = :agent';
            $params['agent'] = $fields['is_support_agent'] ? 1 : 0;
        }
        if (array_key_exists('is_blog_author', $fields)) {
            $sets[] = 'is_blog_author = :blogauthor';
            $params['blogauthor'] = $fields['is_blog_author'] ? 1 : 0;
        }
        if (array_key_exists('avatar_url', $fields)) {
            $sets[] = 'avatar_url = :avatar';
            $params['avatar'] = $fields['avatar_url'] !== null ? (string) $fields['avatar_url'] : null;
        }
        if (array_key_exists('bio', $fields)) {
            $sets[] = 'bio = :bio';
            $params['bio'] = $fields['bio'] !== null ? (string) $fields['bio'] : null;
        }
        if (array_key_exists('customer_id', $fields)) {
            $sets[] = 'customer_id = :cid';
            $params['cid'] = $fields['customer_id'] !== null ? (int) $fields['customer_id'] : null;
        }
        if (array_key_exists('permissions', $fields)) {
            $sets[] = 'permissions = :perms';
            $params['perms'] = json_encode(Permissions::sanitize($fields['permissions']));
        }
        if (array_key_exists('status', $fields)) {
            $sets[] = 'status = :status';
            $params['status'] = (string) $fields['status'];
        }
        if (array_key_exists('must_change_password', $fields)) {
            $sets[] = 'must_change_password = :mcp';
            $params['mcp'] = $fields['must_change_password'] ? 1 : 0;
        }

        if ($sets === []) {
            return;
        }

        $sets[] = 'updated_at = NOW()';
        $stmt = $this->pdo->prepare('UPDATE app_user SET ' . implode(', ', $sets) . ' WHERE id = :id');
        $stmt->execute($params);
    }

    public function updatePassword(int $id, string $passwordHash): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE app_user SET password_hash = :hash, updated_at = NOW() WHERE id = :id'
        );
        $stmt->execute(['hash' => $passwordHash, 'id' => $id]);
    }

    public function delete(int $id): bool
    {
        $stmt = $this->pdo->prepare('DELETE FROM app_user WHERE id = :id');
        $stmt->execute(['id' => $id]);
        return $stmt->rowCount() > 0;
    }

    public function emailExists(string $email, ?int $exceptId = null): bool
    {
        if ($exceptId !== null) {
            $stmt = $this->pdo->prepare('SELECT 1 FROM app_user WHERE email = :email AND id <> :id LIMIT 1');
            $stmt->execute(['email' => $email, 'id' => $exceptId]);
        } else {
            $stmt = $this->pdo->prepare('SELECT 1 FROM app_user WHERE email = :email LIMIT 1');
            $stmt->execute(['email' => $email]);
        }
        return $stmt->fetchColumn() !== false;
    }

    /** @param array<string,mixed> $row */
    private function hydrate(array $row): AppUser
    {
        $decoded = json_decode((string) ($row['permissions'] ?? '[]'), true);

        return new AppUser(
            id: (int) $row['id'],
            email: (string) $row['email'],
            name: $row['name'] !== null ? (string) $row['name'] : null,
            isAdmin: (bool) $row['is_admin'],
            customerId: $row['customer_id'] !== null ? (int) $row['customer_id'] : null,
            permissions: Permissions::sanitize($decoded),
            status: (string) $row['status'],
            passwordHash: (string) $row['password_hash'],
            mustChangePassword: (bool) ($row['must_change_password'] ?? false),
            isSupportAgent: (bool) ($row['is_support_agent'] ?? false),
            isBlogAuthor: (bool) ($row['is_blog_author'] ?? false),
            avatarUrl: isset($row['avatar_url']) && $row['avatar_url'] !== null ? (string) $row['avatar_url'] : null,
            bio: isset($row['bio']) && $row['bio'] !== null ? (string) $row['bio'] : null,
            memberships: $this->membershipsForUser((int) $row['id']),
        );
    }
}
