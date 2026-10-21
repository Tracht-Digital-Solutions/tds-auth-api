<?php
declare(strict_types=1);

namespace Tds\AuthApi\Infrastructure;

use PDO;
use Tds\AuthApi\Service\PasswordResetRepository;

/**
 * Expiry is written and compared with NOW() only — the Berlin-pinned session
 * clock — so no PHP timestamp and no second convention enter a condition.
 */
final class PdoPasswordResetRepository implements PasswordResetRepository
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function create(int $userId, string $tokenHash, int $ttlSeconds): void
    {
        $this->deleteForUser($userId);
        // Expired rows of other users go with every write; the table never grows
        // beyond the tokens that could still be clicked.
        $this->pdo->exec("DELETE FROM auth_password_reset WHERE expires_at < NOW()");

        // The interval is an inlined int: a bound placeholder inside INTERVAL is
        // as unreliable across drivers as a bound LIMIT.
        $stmt = $this->pdo->prepare(
            "INSERT INTO auth_password_reset (token_hash, user_id, expires_at, created_at) "
            . "VALUES (:hash, :uid, NOW() + INTERVAL " . max(60, $ttlSeconds) . " SECOND, NOW())"
        );
        $stmt->execute(['hash' => $tokenHash, 'uid' => $userId]);
    }

    public function consume(string $tokenHash): ?int
    {
        $stmt = $this->pdo->prepare(
            "UPDATE auth_password_reset SET used_at = NOW() "
            . "WHERE token_hash = :hash AND used_at IS NULL AND expires_at > NOW()"
        );
        $stmt->execute(['hash' => $tokenHash]);
        if ($stmt->rowCount() !== 1) {
            return null;
        }

        $read = $this->pdo->prepare("SELECT user_id FROM auth_password_reset WHERE token_hash = :hash LIMIT 1");
        $read->execute(['hash' => $tokenHash]);
        $userId = $read->fetchColumn();
        return $userId === false ? null : (int) $userId;
    }

    public function deleteForUser(int $userId): void
    {
        $stmt = $this->pdo->prepare("DELETE FROM auth_password_reset WHERE user_id = :uid");
        $stmt->execute(['uid' => $userId]);
    }
}
