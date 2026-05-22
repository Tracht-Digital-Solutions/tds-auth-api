<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Service;

use PDO;
use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Service\PdoRateLimiter;

/**
 * Integration test against MariaDB. Mirrors the contact-api equivalent
 * since the implementation is intentionally a paste of the same
 * algorithm. Skipped without TDS_TEST_DB_DSN.
 */
final class PdoRateLimiterTest extends TestCase
{
    private PDO $pdo;

    protected function setUp(): void
    {
        $dsn = getenv('TDS_TEST_DB_DSN') ?: '';
        if ($dsn === '') {
            self::markTestSkipped('Set TDS_TEST_DB_DSN to run rate-limiter integration tests.');
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

        $this->pdo->exec('DROP TABLE IF EXISTS login_attempt');
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE login_attempt (
              id INT UNSIGNED NOT NULL AUTO_INCREMENT,
              bucket VARCHAR(100) NOT NULL,
              created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
              PRIMARY KEY (id),
              KEY idx_bucket_created (bucket, created_at),
              KEY idx_created (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        SQL);
    }

    public function test_allows_under_limit_and_decrements_remaining(): void
    {
        $limiter = new PdoRateLimiter($this->pdo, limit: 3, windowSeconds: 900);

        $first = $limiter->check('admin:203.0.113.1');
        $second = $limiter->check('admin:203.0.113.1');

        self::assertTrue($first['allowed']);
        self::assertSame(2, $first['remaining']);
        self::assertTrue($second['allowed']);
        self::assertSame(1, $second['remaining']);
    }

    public function test_blocks_once_limit_reached(): void
    {
        $limiter = new PdoRateLimiter($this->pdo, limit: 2, windowSeconds: 900);

        $limiter->check('admin:203.0.113.2');
        $limiter->check('admin:203.0.113.2');
        $blocked = $limiter->check('admin:203.0.113.2');

        self::assertFalse($blocked['allowed']);
        self::assertSame(0, $blocked['remaining']);
    }

    public function test_prunes_rows_outside_window(): void
    {
        $limiter = new PdoRateLimiter($this->pdo, limit: 2, windowSeconds: 60);

        $stale = date('Y-m-d H:i:s', time() - 3600);
        $stmt = $this->pdo->prepare('INSERT INTO login_attempt (bucket, created_at) VALUES (?, ?)');
        $stmt->execute(['customer:203.0.113.3', $stale]);
        $stmt->execute(['customer:203.0.113.3', $stale]);

        $result = $limiter->check('customer:203.0.113.3');

        self::assertTrue($result['allowed'], 'stale rows must not count against the limit');
    }

    public function test_admin_and_customer_buckets_are_independent(): void
    {
        $limiter = new PdoRateLimiter($this->pdo, limit: 1, windowSeconds: 900);

        $admin = $limiter->check('admin:203.0.113.10');
        $customer = $limiter->check('customer:203.0.113.10');

        self::assertTrue($admin['allowed']);
        self::assertTrue($customer['allowed'], 'admin + customer share an IP but should not share a bucket');
    }
}
