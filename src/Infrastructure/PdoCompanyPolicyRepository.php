<?php
declare(strict_types=1);

namespace Tds\AuthApi\Infrastructure;

use PDO;
use Tds\AuthApi\Domain\CompanyPolicy;
use Tds\AuthApi\Domain\Permissions;
use Tds\AuthApi\Service\CompanyPolicyRepository;

final class PdoCompanyPolicyRepository implements CompanyPolicyRepository
{
    private const COLUMNS = 'company_id, max_users, allowed_permissions, allow_custom_groups, allow_company_admins';

    public function __construct(private readonly PDO $pdo)
    {
    }

    public function get(int $companyId): CompanyPolicy
    {
        $stmt = $this->pdo->prepare(
            'SELECT ' . self::COLUMNS . ' FROM auth_company_policy WHERE company_id = :cid LIMIT 1'
        );
        $stmt->execute(['cid' => $companyId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? self::hydrate($row) : CompanyPolicy::unrestricted($companyId);
    }

    public function all(): array
    {
        $stmt = $this->pdo->query('SELECT ' . self::COLUMNS . ' FROM auth_company_policy ORDER BY company_id');

        return array_map([self::class, 'hydrate'], $stmt->fetchAll(PDO::FETCH_ASSOC));
    }

    public function save(int $companyId, array $fields): CompanyPolicy
    {
        $current = $this->get($companyId);

        $maxUsers = array_key_exists('maxUsers', $fields)
            ? ($fields['maxUsers'] !== null ? max(0, (int) $fields['maxUsers']) : null)
            : $current->maxUsers;

        // `null` (no ceiling) and `[]` (may grant nothing) are different
        // statements, so the null check has to come before the cast.
        $allowed = $current->allowedPermissions;
        if (array_key_exists('allowedPermissions', $fields)) {
            $allowed = $fields['allowedPermissions'] === null
                ? null
                : Permissions::sanitize($fields['allowedPermissions']);
        }

        $allowGroups = array_key_exists('allowCustomGroups', $fields)
            ? (bool) $fields['allowCustomGroups']
            : $current->allowCustomGroups;

        $allowAdmins = array_key_exists('allowCompanyAdmins', $fields)
            ? (bool) $fields['allowCompanyAdmins']
            : $current->allowCompanyAdmins;

        $stmt = $this->pdo->prepare(
            'INSERT INTO auth_company_policy
                 (company_id, max_users, allowed_permissions, allow_custom_groups, allow_company_admins)
             VALUES (:cid, :max, :allowed, :groups, :admins)
             ON DUPLICATE KEY UPDATE max_users = VALUES(max_users),
                 allowed_permissions = VALUES(allowed_permissions),
                 allow_custom_groups = VALUES(allow_custom_groups),
                 allow_company_admins = VALUES(allow_company_admins)'
        );
        $stmt->execute([
            'cid' => $companyId,
            'max' => $maxUsers,
            'allowed' => $allowed === null ? null : json_encode($allowed),
            'groups' => $allowGroups ? 1 : 0,
            'admins' => $allowAdmins ? 1 : 0,
        ]);

        return new CompanyPolicy($companyId, $maxUsers, $allowed, $allowGroups, $allowAdmins);
    }

    public function seatsUsed(int $companyId): int
    {
        // Disabled users count. Otherwise "disable one, add another" is a free
        // seat, which is the first thing anyone tries.
        $stmt = $this->pdo->prepare(
            'SELECT COUNT(*) AS c FROM app_user_company WHERE company_id = :cid'
        );
        $stmt->execute(['cid' => $companyId]);

        return (int) ($stmt->fetch(PDO::FETCH_ASSOC)['c'] ?? 0);
    }

    public function withSeat(int $companyId, callable $insert): bool
    {
        $this->pdo->beginTransaction();
        try {
            // Lock the policy row so a concurrent create serialises behind us.
            // A plain count-then-insert lets two requests both see "9 of 10"
            // and both write, which is how a seat cap quietly stops being one.
            $lock = $this->pdo->prepare(
                'SELECT max_users FROM auth_company_policy WHERE company_id = :cid FOR UPDATE'
            );
            $lock->execute(['cid' => $companyId]);
            $row = $lock->fetch(PDO::FETCH_ASSOC);

            $max = null;
            if (is_array($row)) {
                $max = $row['max_users'] !== null ? (int) $row['max_users'] : null;
            }

            if ($max !== null && $this->seatsUsed($companyId) >= $max) {
                $this->pdo->rollBack();
                return false;
            }

            $insert();
            $this->pdo->commit();

            return true;
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }

    /** @param array<string,mixed> $row */
    private static function hydrate(array $row): CompanyPolicy
    {
        $allowed = null;
        if ($row['allowed_permissions'] !== null) {
            $allowed = Permissions::hydrate($row['allowed_permissions']);
        }

        return new CompanyPolicy(
            companyId: (int) $row['company_id'],
            maxUsers: $row['max_users'] !== null ? (int) $row['max_users'] : null,
            allowedPermissions: $allowed,
            allowCustomGroups: (bool) $row['allow_custom_groups'],
            allowCompanyAdmins: (bool) ($row['allow_company_admins'] ?? false),
        );
    }
}
