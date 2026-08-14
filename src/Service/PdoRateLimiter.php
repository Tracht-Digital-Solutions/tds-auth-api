<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

use PDO;

/**
 * Persistent sliding-window rate limiter backed by MariaDB. Used to
 * gate `/admin/login` + `/customer/login` against credential-stuffing
 * / brute-force attempts.
 *
 * Mirrors `Tds\ContactApi\Service\PdoRateLimiter` (same shape, same
 * algorithm) — duplicated rather than shared because the two
 * services run in separate PHP repos.
 *
 * Each call:
 *   1. Prunes rows older than `$windowSeconds` for the bucket.
 *   2. Counts what remains.
 *   3. Returns `allowed: false` if the count >= `$limit`,
 *      otherwise inserts a row and returns `allowed: true`.
 *
 * Wrapped in a single transaction so concurrent attempts can't slip
 * past the limit during the prune→count→insert race.
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
        $this->pdo->beginTransaction();
        try {
            $cutoff = date('Y-m-d H:i:s', time() - $this->windowSeconds);

            $del = $this->pdo->prepare(
                "DELETE FROM login_attempt WHERE bucket = :bucket AND created_at < :cutoff"
            );
            $del->execute(['bucket' => $bucket, 'cutoff' => $cutoff]);

            $count = $this->pdo->prepare(
                "SELECT COUNT(*) AS c FROM login_attempt WHERE bucket = :bucket"
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
