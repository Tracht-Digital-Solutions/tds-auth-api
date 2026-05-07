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

    public function record(string $jti, ?int $customerId, bool $admin, int $expiresAtUnix): void
    {
        $stmt = $this->pdo->prepare(
            "INSERT INTO session (jti, customer_id, admin, expires_at, created_at) "
            . "VALUES (:jti, :cid, :admin, FROM_UNIXTIME(:exp), NOW())"
        );
        $stmt->execute([
            'jti' => $jti,
            'cid' => $customerId,
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
}
