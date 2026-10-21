<?php

declare(strict_types=1);

namespace Tds\AuthApi\Tests\Infrastructure;

use PDO;
use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Infrastructure\PdoPasswordResetRepository;

/**
 * Set TDS_TEST_DB_DSN (+ user/pass) to run; skipped otherwise.
 *
 * The DDL mirrors `20261021000001_auth_password_reset.php` column for column —
 * a test that builds its own table only tests itself if the two drift.
 */
final class PdoPasswordResetRepositoryTest extends TestCase
{
    private PDO $pdo;

    protected function setUp(): void
    {
        $dsn = getenv('TDS_TEST_DB_DSN') ?: '';
        if ($dsn === '') {
            self::markTestSkipped('Set TDS_TEST_DB_DSN to run.');
        }
        $this->pdo = new PDO($dsn, getenv('TDS_TEST_DB_USER') ?: null, getenv('TDS_TEST_DB_PASS') ?: null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        $this->pdo->exec('DROP TABLE IF EXISTS auth_password_reset');
        $this->pdo->exec(
            'CREATE TABLE auth_password_reset ('
            . 'token_hash CHAR(64) NOT NULL PRIMARY KEY, '
            . 'user_id INT UNSIGNED NOT NULL, '
            . 'expires_at DATETIME NOT NULL, '
            . 'used_at DATETIME NULL, '
            . 'created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)'
        );
    }

    public function test_a_token_is_consumed_once(): void
    {
        $repo = new PdoPasswordResetRepository($this->pdo);
        $repo->create(7, str_repeat('a', 64), 3600);

        self::assertSame(7, $repo->consume(str_repeat('a', 64)));
        self::assertNull($repo->consume(str_repeat('a', 64)));
        self::assertNull($repo->consume(str_repeat('b', 64)));
    }

    public function test_a_new_token_replaces_the_users_earlier_one(): void
    {
        $repo = new PdoPasswordResetRepository($this->pdo);
        $repo->create(7, str_repeat('a', 64), 3600);
        $repo->create(7, str_repeat('b', 64), 3600);

        self::assertNull($repo->consume(str_repeat('a', 64)));
        self::assertSame(7, $repo->consume(str_repeat('b', 64)));
    }

    public function test_an_expired_token_is_rejected(): void
    {
        $repo = new PdoPasswordResetRepository($this->pdo);
        $repo->create(7, str_repeat('a', 64), 3600);
        $this->pdo->exec("UPDATE auth_password_reset SET expires_at = NOW() - INTERVAL 1 SECOND");

        self::assertNull($repo->consume(str_repeat('a', 64)));
    }
}
