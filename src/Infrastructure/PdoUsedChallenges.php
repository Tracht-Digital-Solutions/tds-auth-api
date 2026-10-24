<?php

declare(strict_types=1);

namespace Tds\AuthApi\Infrastructure;

use PDO;
use PDOException;
use Tds\AuthApi\Service\UsedChallenges;

final class PdoUsedChallenges implements UsedChallenges
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function claim(string $challenge, int $expiresAt): bool
    {
        // Rows only need to outlive the cookie that could replay them.
        if (random_int(1, 50) === 1) {
            $this->pdo->exec('DELETE FROM auth_passkey_challenge WHERE expires_at < NOW()');
        }

        try {
            $this->pdo->prepare(
                'INSERT INTO auth_passkey_challenge (challenge_hash, expires_at) VALUES (:h, FROM_UNIXTIME(:e))'
            )->execute(['h' => hash('sha256', $challenge), 'e' => $expiresAt]);
            return true;
        } catch (PDOException $e) {
            // 23000 = the primary key already holds it: a replay.
            if ($e->getCode() === '23000') {
                return false;
            }
            throw $e;
        }
    }
}
