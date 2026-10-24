<?php
declare(strict_types=1);

namespace Tds\AuthApi\Infrastructure;

use PDO;
use Tds\AuthApi\Service\AccountConfirmRepository;

/**
 * Expiry is written and compared with NOW() only — the Berlin-pinned session
 * clock — like PdoPasswordResetRepository.
 */
final class PdoAccountConfirmRepository implements AccountConfirmRepository
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function create(int $userId, string $tokenHash, string $passwordHash, ?string $name, int $ttlSeconds): void
    {
        // Expired rows go with every write; the table never grows beyond the
        // tokens that could still be clicked.
        $this->pdo->exec("DELETE FROM auth_account_confirm WHERE expires_at < NOW()");
        $stmt = $this->pdo->prepare(
            "INSERT INTO auth_account_confirm (token_hash, user_id, password_hash, name, expires_at, created_at) "
            . "VALUES (:hash, :uid, :pw, :name, NOW() + INTERVAL " . max(60, $ttlSeconds) . " SECOND, NOW())"
        );
        $stmt->execute(['hash' => $tokenHash, 'uid' => $userId, 'pw' => $passwordHash, 'name' => $name]);
    }

    public function consume(string $tokenHash): ?array
    {
        $stmt = $this->pdo->prepare(
            "UPDATE auth_account_confirm SET used_at = NOW() "
            . "WHERE token_hash = :hash AND used_at IS NULL AND expires_at > NOW()"
        );
        $stmt->execute(['hash' => $tokenHash]);
        if ($stmt->rowCount() !== 1) {
            return null;
        }
        $read = $this->pdo->prepare(
            "SELECT user_id, password_hash, name FROM auth_account_confirm WHERE token_hash = :hash LIMIT 1"
        );
        $read->execute(['hash' => $tokenHash]);
        $row = $read->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)) {
            return null;
        }
        return [
            'userId' => (int) $row['user_id'],
            'passwordHash' => (string) $row['password_hash'],
            'name' => $row['name'] !== null ? (string) $row['name'] : null,
        ];
    }

    public function deleteForUser(int $userId): void
    {
        $stmt = $this->pdo->prepare("DELETE FROM auth_account_confirm WHERE user_id = :uid");
        $stmt->execute(['uid' => $userId]);
    }
}
