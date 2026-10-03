<?php

declare(strict_types=1);

namespace Tds\AuthApi\Tests\Infrastructure;

use PDO;
use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Infrastructure\PdoUsedChallenges;

/** Set TDS_TEST_DB_DSN (+ user/pass) to run; skipped otherwise. */
final class PdoUsedChallengesTest extends TestCase
{
    public function test_a_challenge_can_be_claimed_once(): void
    {
        $dsn = getenv('TDS_TEST_DB_DSN') ?: '';
        if ($dsn === '') {
            self::markTestSkipped('Set TDS_TEST_DB_DSN to run.');
        }
        $pdo = new PDO($dsn, getenv('TDS_TEST_DB_USER') ?: null, getenv('TDS_TEST_DB_PASS') ?: null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        $pdo->exec('DROP TABLE IF EXISTS auth_passkey_challenge');
        $pdo->exec('CREATE TABLE auth_passkey_challenge (challenge_hash CHAR(64) NOT NULL PRIMARY KEY, expires_at DATETIME NOT NULL)');

        $used = new PdoUsedChallenges($pdo);
        self::assertTrue($used->claim('raw-challenge-bytes', time() + 300));
        // The replay: same challenge, second time.
        self::assertFalse($used->claim('raw-challenge-bytes', time() + 300));
        self::assertTrue($used->claim('another-challenge', time() + 300));
    }
}
