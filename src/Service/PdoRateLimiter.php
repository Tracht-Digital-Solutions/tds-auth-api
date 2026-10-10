<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

use PDO;

/**
 * Persistent sliding-window rate limiter backed by MariaDB. Used to
 * gate `/admin/login` + `/customer/login` against credential-stuffing
 * / brute-force attempts.
 *
 * Each call:
 *   1. Prunes rows older than `$windowSeconds` for the bucket.
 *   2. Counts what remains.
 *   3. Returns `allowed: false` if the count >= `$limit`,
 *      otherwise inserts a row and returns `allowed: true`.
 *
 * Wrapped in a single transaction, and the count is a LOCKING read
 * (`FOR UPDATE`), so concurrent attempts on one bucket serialise. A plain
 * `SELECT COUNT(*)` does not lock under InnoDB's default isolation, which
 * let parallel guesses past the limit.
 *
 * Buckets longer than the 100-character column are hashed; one in fifty
 * calls also prunes every expired row, so a spray of distinct buckets cannot
 * grow the table without bound.
 */
final class PdoRateLimiter implements RateLimiter
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly int $limit,
        private readonly int $windowSeconds,
    ) {
    }

    /** @return array{allowed: bool, remaining: int} */
    public function check(string $bucket): array
    {
        if (strlen($bucket) > 100) {
            $bucket = substr($bucket, 0, 30) . ':' . hash('sha256', $bucket);
        }

        $this->pdo->beginTransaction();
        try {
            // The cutoff in SQL, in the session zone `created_at` is written
            // in — not PHP's `date()`, which only matched while both were pinned.
            $window = max(1, $this->windowSeconds);
            $pruneAll = random_int(1, 50) === 1;
            $del = $this->pdo->prepare(
                $pruneAll
                    ? "DELETE FROM login_attempt WHERE created_at < NOW() - INTERVAL {$window} SECOND"
                    : "DELETE FROM login_attempt WHERE bucket = :bucket AND created_at < NOW() - INTERVAL {$window} SECOND"
            );
            $del->execute($pruneAll ? [] : ['bucket' => $bucket]);

            $count = $this->pdo->prepare(
                "SELECT COUNT(*) AS c FROM login_attempt WHERE bucket = :bucket FOR UPDATE"
            );
            $count->execute(['bucket' => $bucket]);
            $current = (int) ($count->fetch()['c'] ?? 0);

            if ($current >= $this->limit) {
                $this->pdo->commit();
                return ['allowed' => false, 'remaining' => 0];
            }

            $ins = $this->pdo->prepare(
                "INSERT INTO login_attempt (bucket, created_at) VALUES (:bucket, NOW())"
            );
            $ins->execute(['bucket' => $bucket]);

            $this->pdo->commit();
            return ['allowed' => true, 'remaining' => $this->limit - $current - 1];
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }
}
