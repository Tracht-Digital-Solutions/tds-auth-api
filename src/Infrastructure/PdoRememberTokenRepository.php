<?php
declare(strict_types=1);

namespace Tds\AuthApi\Infrastructure;

use PDO;
use Tds\AuthApi\Service\RememberTokenRepository;

final class PdoRememberTokenRepository implements RememberTokenRepository
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function store(int $userId, string $selector, string $validatorHash, int $expiresAtUnix, ?string $userAgent): void
    {
        $stmt = $this->pdo->prepare(
            "INSERT INTO app_user_remember (user_id, selector, validator_hash, expires_at, created_at, user_agent) "
            . "VALUES (:uid, :sel, :hash, FROM_UNIXTIME(:exp), NOW(), :ua)"
        );
        $stmt->execute([
            'uid' => $userId,
            'sel' => $selector,
            'hash' => $validatorHash,
            'exp' => $expiresAtUnix,
            'ua' => $userAgent,
        ]);
    }

    public function findBySelector(string $selector): ?array
    {
        $stmt = $this->pdo->prepare(
            "SELECT user_id, validator_hash, UNIX_TIMESTAMP(expires_at) AS expires_at "
            . "FROM app_user_remember WHERE selector = :sel LIMIT 1"
        );
        $stmt->execute(['sel' => $selector]);
        $row = $stmt->fetch();
        if ($row === false) {
            return null;
        }
        return [
            'user_id' => (int) $row['user_id'],
            'validator_hash' => (string) $row['validator_hash'],
            'expires_at' => (int) $row['expires_at'],
        ];
    }

    public function deleteBySelector(string $selector): void
    {
        $stmt = $this->pdo->prepare("DELETE FROM app_user_remember WHERE selector = :sel");
        $stmt->execute(['sel' => $selector]);
    }

    public function deleteForUser(int $userId): void
    {
        $stmt = $this->pdo->prepare("DELETE FROM app_user_remember WHERE user_id = :uid");
        $stmt->execute(['uid' => $userId]);
    }

    public function purgeExpired(): void
    {
        $this->pdo->exec("DELETE FROM app_user_remember WHERE expires_at < NOW()");
    }
}
