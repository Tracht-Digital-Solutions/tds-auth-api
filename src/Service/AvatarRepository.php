<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

/**
 * Storage for profile pictures (`app_user_avatar`).
 *
 * The bytes live in the database — see the migration for why. Reads are split
 * in two on purpose: {@see self::meta()} answers "is there one, and has it
 * changed" for the conditional-request path without pulling a MEDIUMBLOB into
 * PHP memory, and {@see self::find()} is only reached on an actual cache miss.
 */
interface AvatarRepository
{
    /**
     * Metadata only — no bytes. Used for the ETag/304 path and for the
     * `hasAvatar` flag on `/me`.
     *
     * @return array{mime_type: string, size_bytes: int, updated_at: string}|null
     */
    public function meta(int $userId): ?array;

    /**
     * The image itself.
     *
     * @return array{mime_type: string, size_bytes: int, updated_at: string, content: string}|null
     */
    public function find(int $userId): ?array;

    /** Insert or replace this user's avatar. */
    public function put(int $userId, string $content, string $mimeType): void;

    /** Remove it. Idempotent — deleting a missing avatar is not an error. */
    public function delete(int $userId): void;
}
