<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Infrastructure;

use PDO;
use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Infrastructure\PdoAppUserRepository;

/**
 * Integration test for the membership SQL against MariaDB. Set TDS_TEST_DB_DSN
 * (+ user/pass) to run, skipped otherwise. Exercises the create → membership
 * insert, setMemberships replace + primary-column sync, and membership loading
 * on find that the Fake repo can't validate.
 */
final class PdoAppUserRepositoryTest extends TestCase
{
    private PDO $pdo;
    private PdoAppUserRepository $repo;

    protected function setUp(): void
    {
        $dsn = getenv('TDS_TEST_DB_DSN') ?: '';
        if ($dsn === '') {
            self::markTestSkipped('Set TDS_TEST_DB_DSN to run app-user repository tests.');
        }

        $this->pdo = new PDO(
            $dsn,
            getenv('TDS_TEST_DB_USER') ?: null,
            getenv('TDS_TEST_DB_PASS') ?: null,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC],
        );

        $this->pdo->exec('SET FOREIGN_KEY_CHECKS = 0');
        $this->pdo->exec('DROP TABLE IF EXISTS app_user_customer');
        $this->pdo->exec('DROP TABLE IF EXISTS app_user');
        $this->pdo->exec('SET FOREIGN_KEY_CHECKS = 1');
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE app_user (
              id INT UNSIGNED NOT NULL AUTO_INCREMENT,
              email VARCHAR(254) NOT NULL,
              password_hash VARCHAR(255) NOT NULL,
              name VARCHAR(200) NULL,
              is_admin TINYINT(1) NOT NULL DEFAULT 0,
              is_support_agent TINYINT(1) NOT NULL DEFAULT 0,
              customer_id INT UNSIGNED NULL,
              permissions TEXT NOT NULL,
              status VARCHAR(20) NOT NULL DEFAULT 'active',
              must_change_password TINYINT(1) NOT NULL DEFAULT 0,
              created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
              PRIMARY KEY (id),
              UNIQUE KEY uniq_email (email)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        SQL);
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE app_user_customer (
              id INT UNSIGNED NOT NULL AUTO_INCREMENT,
              user_id INT UNSIGNED NOT NULL,
              customer_id INT UNSIGNED NOT NULL,
              permissions TEXT NOT NULL,
              created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
              PRIMARY KEY (id),
              UNIQUE KEY uniq_user_customer (user_id, customer_id),
              KEY idx_user (user_id),
              CONSTRAINT fk_auc_user FOREIGN KEY (user_id) REFERENCES app_user (id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        SQL);

        $this->repo = new PdoAppUserRepository($this->pdo);
    }

    public function test_create_with_customer_inserts_one_membership(): void
    {
        $id = $this->repo->create('a@example.com', 'hash', 'A', false, 7, ['invoices:read'], 'active');

        $user = $this->repo->findById($id);
        self::assertNotNull($user);
        self::assertCount(1, $user->memberships);
        self::assertSame(7, $user->memberships[0]->customerId);
        self::assertSame(['invoices:read'], $user->memberships[0]->permissions);
        self::assertSame(7, $user->customerId);
    }

    public function test_create_admin_without_customer_has_no_membership(): void
    {
        $id = $this->repo->create('admin@example.com', 'hash', 'Admin', true, null, [], 'active');

        $user = $this->repo->findById($id);
        self::assertNotNull($user);
        self::assertSame([], $user->memberships);
        self::assertNull($user->customerId);
    }

    public function test_set_memberships_replaces_and_syncs_primary(): void
    {
        $id = $this->repo->create('multi@example.com', 'hash', 'Multi', false, 1, ['tickets:read'], 'active');

        $this->repo->setMemberships($id, [
            ['customerId' => 3, 'permissions' => ['tickets:read', 'tickets:write']],
            ['customerId' => 5, 'permissions' => ['invoices:read']],
        ]);

        $user = $this->repo->findById($id);
        self::assertNotNull($user);
        self::assertCount(2, $user->memberships);
        // Primary columns follow the first membership.
        self::assertSame(3, $user->customerId);
        self::assertSame(['tickets:read', 'tickets:write'], $user->permissions);
        // The old company-1 membership is gone.
        $cids = array_map(fn ($m) => $m->customerId, $user->memberships);
        self::assertSame([3, 5], $cids);
    }

    public function test_set_memberships_sanitises_unknown_permissions(): void
    {
        $id = $this->repo->create('s@example.com', 'hash', null, false, 2, [], 'active');

        $this->repo->setMemberships($id, [
            ['customerId' => 2, 'permissions' => ['invoices:read', 'invoices:delete']],
        ]);

        $user = $this->repo->findById($id);
        self::assertSame(['invoices:read'], $user?->memberships[0]->permissions);
    }

    public function test_set_memberships_to_empty_clears_primary(): void
    {
        $id = $this->repo->create('c@example.com', 'hash', null, false, 2, ['invoices:read'], 'active');

        $this->repo->setMemberships($id, []);

        $user = $this->repo->findById($id);
        self::assertSame([], $user?->memberships);
        self::assertNull($user?->customerId);
    }
}
