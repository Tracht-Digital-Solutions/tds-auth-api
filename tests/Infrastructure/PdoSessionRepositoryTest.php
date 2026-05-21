<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Infrastructure;

use PDO;
use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Infrastructure\PdoSessionRepository;

/**
 * Integration test against MariaDB. Set TDS_TEST_DB_DSN (+ user/pass) to
 * run, skipped otherwise.
 */
final class PdoSessionRepositoryTest extends TestCase
{
    private PDO $pdo;
    private PdoSessionRepository $repo;

    protected function setUp(): void
    {
        $dsn = getenv('TDS_TEST_DB_DSN') ?: '';
        if ($dsn === '') {
            self::markTestSkipped('Set TDS_TEST_DB_DSN to run session repository tests.');
        }

        $this->pdo = new PDO(
            $dsn,
            getenv('TDS_TEST_DB_USER') ?: null,
            getenv('TDS_TEST_DB_PASS') ?: null,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ],
        );

        $this->pdo->exec('DROP TABLE IF EXISTS session');
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE session (
              jti VARCHAR(36) NOT NULL,
              customer_id INT NULL,
              admin TINYINT(1) NOT NULL DEFAULT 0,
              expires_at DATETIME NOT NULL,
              created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
              revoked_at DATETIME NULL,
              PRIMARY KEY (jti),
              KEY idx_customer_id (customer_id),
              KEY idx_expires_at (expires_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        SQL);

        $this->repo = new PdoSessionRepository($this->pdo);
    }

    public function test_record_then_isRevoked_returns_false(): void
    {
        $this->repo->record('jti-1', null, true, time() + 900);

        self::assertFalse($this->repo->isRevoked('jti-1'));
    }

    public function test_unknown_jti_treated_as_revoked(): void
    {
        self::assertTrue($this->repo->isRevoked('does-not-exist'));
    }

    public function test_revoke_marks_session_revoked(): void
    {
        $this->repo->record('jti-2', 42, false, time() + 900);
        $this->repo->revoke('jti-2');

        self::assertTrue($this->repo->isRevoked('jti-2'));
    }

    public function test_revoke_idempotent_for_already_revoked(): void
    {
        $this->repo->record('jti-3', null, true, time() + 900);
        $this->repo->revoke('jti-3');
        $this->repo->revoke('jti-3');

        self::assertTrue($this->repo->isRevoked('jti-3'));
    }

    public function test_record_persists_customer_id_and_admin_flag(): void
    {
        $this->repo->record('jti-4', 99, false, time() + 900);

        $row = $this->pdo->query("SELECT customer_id, admin FROM session WHERE jti = 'jti-4'")->fetch();
        self::assertSame(99, (int) $row['customer_id']);
        self::assertSame(0, (int) $row['admin']);
    }
}
