<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Support;

use Tds\AuthApi\Service\AvatarRepository;

/**
 * In-memory avatar store. Keeps the same split as the PDO implementation —
 * {@see self::meta()} never returns bytes — so a test cannot accidentally rely
 * on metadata carrying the content.
 */
final class FakeAvatarRepository implements AvatarRepository
{
    /** @var array<int, array{mime_type:string, size_bytes:int, updated_at:string, content:string}> */
    public array $avatars = [];

    /** @var list<int> */
    public array $deleted = [];

    public function meta(int $userId): ?array
    {
        $row = $this->avatars[$userId] ?? null;
        if ($row === null) {
            return null;
        }
        return [
            'mime_type' => $row['mime_type'],
            'size_bytes' => $row['size_bytes'],
            'updated_at' => $row['updated_at'],
        ];
    }

    public function find(int $userId): ?array
    {
        return $this->avatars[$userId] ?? null;
    }

    public function put(int $userId, string $content, string $mimeType): void
    {
        $this->avatars[$userId] = [
            'mime_type' => $mimeType,
            'size_bytes' => strlen($content),
            'updated_at' => date('Y-m-d H:i:s'),
            'content' => $content,
        ];
    }

    public function delete(int $userId): void
    {
        $this->deleted[] = $userId;
        unset($this->avatars[$userId]);
    }
}
