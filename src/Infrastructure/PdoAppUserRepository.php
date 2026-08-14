<?php
declare(strict_types=1);

namespace Tds\AuthApi\Infrastructure;

use PDO;
use Tds\AuthApi\Domain\AppUser;
use Tds\AuthApi\Domain\Membership;
use Tds\AuthApi\Domain\Permissions;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\GroupRepository;

final class PdoAppUserRepository implements AppUserRepository
{
    private const COLUMNS = 'id, email, password_hash, name, display_name, avatar_url, bio, is_admin, is_support_agent, is_blog_author, company_id, permissions, status, must_change_password';

    /**
     * `$groups` is optional so this repository still constructs with a bare
     * PDO — the create-admin script and several tests do exactly that, and a
     * user's identity does not depend on their groups. Without it,
     * memberships simply carry no `groupIds`.
     */
    public function __construct(
        private readonly PDO $pdo,
        private readonly ?GroupRepository $groups = null,
    ) {
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

    public function list(?int $companyId = null): array
    {
        if ($companyId !== null) {
            // JOIN the membership table, do NOT filter `app_user.company_id`.
            // That column is the DENORMALISED primary membership, so filtering
            // on it missed anyone whose second or third membership was the
            // company being asked about — a user genuinely in company 7 simply
            // did not appear under `?company_id=7`, which is the whole point of
            // the filter. The DISTINCT guards against a user matching twice if
            // duplicate rows ever slip past the unique index.
            $stmt = $this->pdo->prepare(
                'SELECT DISTINCT ' . implode(', ', array_map(
                    static fn (string $c): string => 'u.' . $c,
                    explode(', ', self::COLUMNS),
                )) . '
                 FROM app_user u
                 JOIN app_user_company m ON m.user_id = u.id
                 WHERE m.company_id = :cid
                 ORDER BY u.id DESC'
            );
            $stmt->execute(['cid' => $companyId]);
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
        ?int $companyId,
        array $permissions,
        string $status = 'active',
    ): int {
        $perms = Permissions::sanitize($permissions);
        $stmt = $this->pdo->prepare(
            'INSERT INTO app_user (email, password_hash, name, is_admin, company_id, permissions, status, created_at, updated_at) '
            . 'VALUES (:email, :hash, :name, :admin, :cid, :perms, :status, NOW(), NOW())'
        );
        $stmt->execute([
            'email' => $email,
            'hash' => $passwordHash,
            'name' => $name,
            'admin' => $isAdmin ? 1 : 0,
            'cid' => $companyId,
            'perms' => json_encode($perms),
            'status' => $status,
        ]);

        $id = (int) $this->pdo->lastInsertId();

        // Mirror the primary company as a membership row so the many-to-many
        // is the single source of truth from creation onward.
        //
        // NOT dead code: the admin user editor passes `null` here and calls
        // `setMemberships()` afterwards, but the service-token onboarding route
        // (`POST /admin/customer-credentials`, used by tds-customer-api) passes
        // a real id and nothing else. Without this the account would have
        // `app_user.company_id` set and no membership at all, so its token
        // would carry an empty `companies` claim and the portal would show it
        // nothing.
        if ($companyId !== null) {
            $ins = $this->pdo->prepare(
                'INSERT INTO app_user_company (user_id, company_id, permissions, created_at) '
                . 'VALUES (:uid, :cid, :perms, NOW())'
            );
            $ins->execute(['uid' => $id, 'cid' => $companyId, 'perms' => json_encode($perms)]);
        }

        return $id;
    }

    public function setMemberships(int $userId, array $memberships): void
    {
        // Normalise + de-dupe by company (last wins), preserving order.
        $byCompany = [];
        foreach ($memberships as $m) {
            // `customerId` stays accepted for one release — see PermissionAliases.
            $cid = (int) ($m['companyId'] ?? $m['customerId'] ?? 0);
            if ($cid <= 0) {
                continue;
            }
            $byCompany[$cid] = [
                'permissions' => Permissions::sanitize($m['permissions'] ?? []),
                'isCompanyAdmin' => (bool) ($m['isCompanyAdmin'] ?? false),
                'ceiling' => array_key_exists('permissionCeiling', $m) && $m['permissionCeiling'] !== null
                    ? Permissions::sanitize($m['permissionCeiling'])
                    : null,
                // No null/[] distinction here, unlike the ceiling: an empty
                // deny list and no deny list say the same thing.
                'denies' => Permissions::sanitize($m['permissionDenies'] ?? []),
            ];
        }

        $this->pdo->beginTransaction();
        try {
            $del = $this->pdo->prepare('DELETE FROM app_user_company WHERE user_id = :uid');
            $del->execute(['uid' => $userId]);

            $ins = $this->pdo->prepare(
                'INSERT INTO app_user_company '
                . '(user_id, company_id, is_company_admin, permissions, permission_ceiling, permission_denies, created_at) '
                . 'VALUES (:uid, :cid, :cadmin, :perms, :ceiling, :denies, NOW())'
            );
            foreach ($byCompany as $cid => $row) {
                $ins->execute([
                    'uid' => $userId,
                    'cid' => $cid,
                    'cadmin' => $row['isCompanyAdmin'] ? 1 : 0,
                    'perms' => json_encode($row['permissions']),
                    'ceiling' => $row['ceiling'] === null ? null : json_encode($row['ceiling']),
                    'denies' => json_encode($row['denies']),
                ]);
            }

            // Sync the denormalised primary columns to the first membership.
            $primaryCid = null;
            $primaryPerms = [];
            foreach ($byCompany as $cid => $row) {
                $primaryCid = $cid;
                $primaryPerms = $row['permissions'];
                break;
            }
            $sync = $this->pdo->prepare(
                'UPDATE app_user SET company_id = :cid, permissions = :perms, updated_at = NOW() WHERE id = :uid'
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

    public function setCompanyMembership(
        int $userId,
        int $companyId,
        array $permissions,
        bool $isCompanyAdmin,
        ?array $permissionCeiling = null,
        bool $updateCeiling = false,
        array $permissionDenies = [],
    ): void {
        // A single-row upsert, and the ONLY membership write a company-scoped
        // route may reach. `setMemberships()` above replaces the user's whole
        // set — reachable from `/company/*` it would let one company's admin
        // delete a user's membership of another company with a payload that
        // never mentioned it.
        $sql = 'INSERT INTO app_user_company
                    (user_id, company_id, is_company_admin, permissions, permission_ceiling, permission_denies, created_at)
                VALUES (:uid, :cid, :cadmin, :perms, :ceiling, :denies, NOW())
                ON DUPLICATE KEY UPDATE is_company_admin = VALUES(is_company_admin),
                    permissions = VALUES(permissions),
                    permission_denies = VALUES(permission_denies)';
        // The ceiling is the platform admin's limit and is NOT written by a
        // company-scoped route, hence the opt-in flag. The denies are always
        // written: they are the ordinary decision about this person, and a
        // company admin owns it.
        if ($updateCeiling) {
            $sql .= ', permission_ceiling = VALUES(permission_ceiling)';
        }

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            'uid' => $userId,
            'cid' => $companyId,
            'cadmin' => $isCompanyAdmin ? 1 : 0,
            'perms' => json_encode(Permissions::sanitize($permissions)),
            'ceiling' => $permissionCeiling === null ? null : json_encode(Permissions::sanitize($permissionCeiling)),
            'denies' => json_encode(Permissions::sanitize($permissionDenies)),
        ]);
    }

    public function removeCompanyMembership(int $userId, int $companyId): bool
    {
        // Removes the MEMBERSHIP, never the `app_user` row: a login can belong
        // to several companies, and deleting it here would take away access to
        // every other one. An account left with no memberships can still sign
        // in and simply sees nothing until a platform admin cleans up.
        $stmt = $this->pdo->prepare(
            'DELETE FROM app_user_company WHERE user_id = :uid AND company_id = :cid'
        );
        $stmt->execute(['uid' => $userId, 'cid' => $companyId]);

        return $stmt->rowCount() > 0;
    }

    public function companyAdminCount(int $companyId): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT COUNT(*) AS c FROM app_user_company WHERE company_id = :cid AND is_company_admin = 1'
        );
        $stmt->execute(['cid' => $companyId]);

        return (int) ($stmt->fetch(PDO::FETCH_ASSOC)['c'] ?? 0);
    }

    /** @return list<Membership> */
    private function membershipsForUser(int $userId): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT company_id, is_company_admin, permissions, permission_ceiling, permission_denies
             FROM app_user_company WHERE user_id = :uid ORDER BY id ASC'
        );
        $stmt->execute(['uid' => $userId]);

        $assignments = $this->groups?->assignmentsForUser($userId) ?? [];

        $out = [];
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $companyId = (int) $row['company_id'];
            $out[] = new Membership(
                companyId: $companyId,
                // `hydrate`, NOT `sanitize`. Filtering on read means a catalog
                // change retroactively rewrites what the database says — which
                // is exactly how a legitimately granted key disappeared from a
                // token without any write ever happening. Write is the single
                // choke point.
                permissions: Permissions::hydrate($row['permissions']),
                isCompanyAdmin: (bool) ($row['is_company_admin'] ?? false),
                groupIds: array_values(array_unique(array_merge(
                    $assignments[$companyId] ?? [],
                    // Scope 0 is a global assignment: it applies here too.
                    $assignments[0] ?? [],
                ))),
                permissionCeiling: $row['permission_ceiling'] !== null
                    ? Permissions::hydrate($row['permission_ceiling'])
                    : null,
                permissionDenies: Permissions::hydrate($row['permission_denies'] ?? null),
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
        if (array_key_exists('display_name', $fields)) {
            $sets[] = 'display_name = :displayname';
            $params['displayname'] = $fields['display_name'] !== null
                ? (string) $fields['display_name']
                : null;
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
        if (array_key_exists('company_id', $fields)) {
            $sets[] = 'company_id = :cid';
            $params['cid'] = $fields['company_id'] !== null ? (int) $fields['company_id'] : null;
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
        return new AppUser(
            id: (int) $row['id'],
            email: (string) $row['email'],
            name: $row['name'] !== null ? (string) $row['name'] : null,
            isAdmin: (bool) $row['is_admin'],
            companyId: $row['company_id'] !== null ? (int) $row['company_id'] : null,
            // hydrate(), not sanitize() — see membershipsForUser().
            permissions: Permissions::hydrate($row['permissions']),
            status: (string) $row['status'],
            passwordHash: (string) $row['password_hash'],
            mustChangePassword: (bool) ($row['must_change_password'] ?? false),
            isSupportAgent: (bool) ($row['is_support_agent'] ?? false),
            isBlogAuthor: (bool) ($row['is_blog_author'] ?? false),
            avatarUrl: isset($row['avatar_url']) && $row['avatar_url'] !== null ? (string) $row['avatar_url'] : null,
            bio: isset($row['bio']) && $row['bio'] !== null ? (string) $row['bio'] : null,
            memberships: $this->membershipsForUser((int) $row['id']),
            displayName: isset($row['display_name']) && $row['display_name'] !== null
                ? (string) $row['display_name']
                : null,
        );
    }
}
