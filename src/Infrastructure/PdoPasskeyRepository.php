<?php
declare(strict_types=1);

namespace Tds\AuthApi\Infrastructure;

use PDO;
use Tds\AuthApi\Service\PasskeyRepository;

final class PdoPasskeyRepository implements PasskeyRepository
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function findByCredentialId(string $credentialId): ?array
    {
        $stmt = $this->pdo->prepare(
            "SELECT id, user_id, credential_id, public_key, sign_count, name "
            . "FROM app_user_passkey WHERE credential_id = :cid LIMIT 1"
        );
        $stmt->execute(['cid' => $credentialId]);
        $row = $stmt->fetch();
        if ($row === false) {
            return null;
        }
        return [
            'id' => (int) $row['id'],
            'user_id' => (int) $row['user_id'],
            'credential_id' => (string) $row['credential_id'],
            'public_key' => (string) $row['public_key'],
            'sign_count' => (int) $row['sign_count'],
            'name' => $row['name'] !== null ? (string) $row['name'] : null,
        ];
    }

    public function listForUser(int $userId): array
    {
        $stmt = $this->pdo->prepare(
            "SELECT id, credential_id, name, created_at, last_used_at "
            . "FROM app_user_passkey WHERE user_id = :uid ORDER BY created_at DESC"
        );
        $stmt->execute(['uid' => $userId]);
        $out = [];
        foreach ($stmt->fetchAll() as $row) {
            $out[] = [
                'id' => (int) $row['id'],
                'credential_id' => (string) $row['credential_id'],
                'name' => $row['name'] !== null ? (string) $row['name'] : null,
                'created_at' => (string) $row['created_at'],
                'last_used_at' => $row['last_used_at'] !== null ? (string) $row['last_used_at'] : null,
            ];
        }
        return $out;
    }

    public function credentialIdsForUser(int $userId): array
    {
        $stmt = $this->pdo->prepare("SELECT credential_id FROM app_user_passkey WHERE user_id = :uid");
        $stmt->execute(['uid' => $userId]);
        return array_map(static fn ($r): string => (string) $r['credential_id'], $stmt->fetchAll());
    }

    public function store(int $userId, string $credentialId, string $publicKeyPem, int $signCount, ?string $name): void
    {
        $stmt = $this->pdo->prepare(
            "INSERT INTO app_user_passkey (user_id, credential_id, public_key, sign_count, name, created_at) "
            . "VALUES (:uid, :cid, :pk, :cnt, :name, NOW())"
        );
        $stmt->execute([
            'uid' => $userId,
            'cid' => $credentialId,
            'pk' => $publicKeyPem,
            'cnt' => $signCount,
            'name' => $name,
        ]);
    }

    public function touch(int $id, int $signCount): void
    {
        $stmt = $this->pdo->prepare(
            "UPDATE app_user_passkey SET sign_count = :cnt, last_used_at = NOW() WHERE id = :id"
        );
        $stmt->execute(['cnt' => $signCount, 'id' => $id]);
    }

    public function deleteForUser(int $id, int $userId): bool
    {
        // The user_id predicate is the authorisation check, not a filter: without
        // it an id guess deletes another account's passkey.
        $stmt = $this->pdo->prepare("DELETE FROM app_user_passkey WHERE id = :id AND user_id = :uid");
        $stmt->execute(['id' => $id, 'uid' => $userId]);
        return $stmt->rowCount() > 0;
    }
}
