<?php

declare(strict_types=1);

namespace Tds\AuthApi\Infrastructure;

use PDO;

/**
 * Run a unit of work in a transaction — or inside the one already open.
 *
 * PDO has no nested transactions: `beginTransaction()` inside an open one
 * throws "There is already an active transaction". The repositories each
 * opened their own, so composing two of them (the company seat check around a
 * group assignment) failed on every call. A repository method now JOINS an
 * outer transaction and only commits or rolls back the one it started.
 */
final class Transaction
{
    /**
     * @template T
     * @param callable(): T $work
     * @return T
     */
    public static function run(PDO $pdo, callable $work): mixed
    {
        if ($pdo->inTransaction()) {
            return $work();
        }

        $pdo->beginTransaction();
        try {
            $result = $work();
            $pdo->commit();
            return $result;
        } catch (\Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
    }
}
