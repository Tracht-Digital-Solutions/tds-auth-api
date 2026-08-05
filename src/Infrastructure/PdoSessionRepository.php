<?php
declare(strict_types=1);

namespace Tds\AuthApi\Infrastructure;

use PDO;
use Tds\AuthApi\Service\SessionRepository;

final class PdoSessionRepository implements SessionRepository
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function record(string $jti, ?int $customerId, bool $admin, int $expiresAtUnix, ?int $userId = null): void
    {
        $stmt = $this->pdo->prepare(
            // NOW(6), not NOW(): the column is DATETIME(6) so that listActive()
            // can order by real recency. NOW() would write `.000000` on every
            // row and silently reinstate the same-second tie this fixed.
            "INSERT INTO session (jti, customer_id, user_id, admin, expires_at, created_at) "
            . "VALUES (:jti, :cid, :uid, :admin, FROM_UNIXTIME(:exp), NOW(6))"
        );
        $stmt->execute([
            'jti' => $jti,
            'cid' => $customerId,
            'uid' => $userId,
            'admin' => $admin ? 1 : 0,
            'exp' => $expiresAtUnix,
        ]);
    }

    public function isRevoked(string $jti): bool
    {
        $stmt = $this->pdo->prepare(
            "SELECT revoked_at FROM session WHERE jti = :jti LIMIT 1"
        );
        $stmt->execute(['jti' => $jti]);
        $row = $stmt->fetch();
        if ($row === false) {
            return true; // unknown jti — treat as revoked
        }
        return $row['revoked_at'] !== null;
    }

    public function revoke(string $jti): void
    {
        $stmt = $this->pdo->prepare(
            "UPDATE session SET revoked_at = NOW() WHERE jti = :jti AND revoked_at IS NULL"
        );
        $stmt->execute(['jti' => $jti]);
    }

    public function revokeAllForUser(int $userId): void
    {
        $stmt = $this->pdo->prepare(
            "UPDATE session SET revoked_at = NOW() WHERE user_id = :uid AND revoked_at IS NULL"
        );
        $stmt->execute(['uid' => $userId]);
    }

    public function listActive(int $limit = 200): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT jti, customer_id, admin, expires_at, created_at '
            . 'FROM session '
            . 'WHERE revoked_at IS NULL AND expires_at > NOW() '
            // created_at is DATETIME(6) and written with NOW(6), so this really
            // is newest-first — the promise the method makes. The jti tiebreaker
            // stays as the last resort for an exact microsecond tie, which keeps
            // the ordering total. (It was carrying the whole sort while the
            // column was 1-second resolution, and a UUIDv4 is random, so
            // same-second sessions came back in an order unrelated to recency.)
            . 'ORDER BY created_at DESC, jti DESC '
            . 'LIMIT :lim'
        );
        $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
        $stmt->execute();

        $rows = $stmt->fetchAll();
        return array_map(static fn (array $r) => [
            'jti' => (string) $r['jti'],
            'customer_id' => $r['customer_id'] !== null ? (int) $r['customer_id'] : null,
            'admin' => (bool) $r['admin'],
            'expires_at' => (string) $r['expires_at'],
            'created_at' => (string) $r['created_at'],
        ], $rows);
    }
}
