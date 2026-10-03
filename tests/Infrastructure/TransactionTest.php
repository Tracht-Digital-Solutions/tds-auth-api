<?php

declare(strict_types=1);

namespace Tds\AuthApi\Tests\Infrastructure;

use PDO;
use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Infrastructure\Transaction;

/**
 * Runs against SQLite in memory: what is pinned is PDO's transaction state,
 * which behaves the same on every driver.
 */
final class TransactionTest extends TestCase
{
    private PDO $pdo;

    protected function setUp(): void
    {
        if (!in_array('sqlite', PDO::getAvailableDrivers(), true)) {
            self::markTestSkipped('pdo_sqlite not available');
        }
        $this->pdo = new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
        $this->pdo->exec('CREATE TABLE t (v INTEGER)');
    }

    public function test_joins_an_outer_transaction_instead_of_opening_a_second(): void
    {
        // The company seat check wraps the group assignment; PDO threw
        // "There is already an active transaction" on every such call.
        $this->pdo->beginTransaction();
        Transaction::run($this->pdo, fn () => $this->pdo->exec('INSERT INTO t VALUES (1)'));
        self::assertTrue($this->pdo->inTransaction(), 'the inner unit must not commit the outer one');
        $this->pdo->rollBack();

        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM t')->fetchColumn());
    }

    public function test_commits_and_rolls_back_its_own(): void
    {
        Transaction::run($this->pdo, fn () => $this->pdo->exec('INSERT INTO t VALUES (1)'));
        try {
            Transaction::run($this->pdo, function (): void {
                $this->pdo->exec('INSERT INTO t VALUES (2)');
                throw new \RuntimeException('boom');
            });
        } catch (\RuntimeException) {
        }

        self::assertSame(['1'], array_map('strval', $this->pdo->query('SELECT v FROM t')->fetchAll(PDO::FETCH_COLUMN)));
        self::assertFalse($this->pdo->inTransaction());
    }
}
