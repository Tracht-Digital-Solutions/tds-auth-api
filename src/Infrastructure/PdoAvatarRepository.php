<?php
declare(strict_types=1);

namespace Tds\AuthApi\Infrastructure;

use PDO;
use Tds\AuthApi\Service\AvatarRepository;

final class PdoAvatarRepository implements AvatarRepository
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function meta(int $userId): ?array
    {
        // Deliberately does NOT select `content`. This runs on every /me and on
        // every conditional GET of an avatar; pulling a MEDIUMBLOB through PDO
        // to decide whether to send a 304 would defeat the point of the ETag.
        $stmt = $this->pdo->prepare(
            'SELECT mime_type, size_bytes, updated_at FROM app_user_avatar WHERE user_id = :uid LIMIT 1'
        );
        $stmt->execute(['uid' => $userId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? [
            'mime_type' => (string) $row['mime_type'],
            'size_bytes' => (int) $row['size_bytes'],
            'updated_at' => (string) $row['updated_at'],
        ] : null;
    }

    public function find(int $userId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT mime_type, size_bytes, updated_at, content FROM app_user_avatar WHERE user_id = :uid LIMIT 1'
        );
        $stmt->execute(['uid' => $userId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!is_array($row)) {
            return null;
        }

        // A BLOB comes back as a stream when PDO::ATTR_STRINGIFY_FETCHES is off
        // on some drivers. Normalise so callers only ever see a string.
        $content = $row['content'];
        if (is_resource($content)) {
            $content = (string) stream_get_contents($content);
        }

        return [
            'mime_type' => (string) $row['mime_type'],
            'size_bytes' => (int) $row['size_bytes'],
            'updated_at' => (string) $row['updated_at'],
            'content' => (string) $content,
        ];
    }

    public function put(int $userId, string $content, string $mimeType): void
    {
        // `user_id` is the primary key, so this is a genuine upsert: replacing
        // a picture reuses the row instead of growing the table. `updated_at`
        // is bumped explicitly because ON UPDATE CURRENT_TIMESTAMP does not
        // fire when every other column happens to be identical — re-uploading
        // the same image must still bust the `?v=` cache.
        $stmt = $this->pdo->prepare(
            'INSERT INTO app_user_avatar (user_id, mime_type, size_bytes, content, updated_at) '
            . 'VALUES (:uid, :mime, :size, :content, NOW()) '
            . 'ON DUPLICATE KEY UPDATE mime_type = VALUES(mime_type), '
            . 'size_bytes = VALUES(size_bytes), content = VALUES(content), updated_at = NOW()'
        );
        $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
        $stmt->bindValue(':mime', $mimeType);
        $stmt->bindValue(':size', strlen($content), PDO::PARAM_INT);
        $stmt->bindValue(':content', $content, PDO::PARAM_LOB);
        $stmt->execute();
    }

    public function delete(int $userId): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM app_user_avatar WHERE user_id = :uid');
        $stmt->execute(['uid' => $userId]);
    }
}
