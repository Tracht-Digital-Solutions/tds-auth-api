<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

/**
 * One-time password-reset tokens, stored as SHA-256 hashes only.
 */
interface PasswordResetRepository
{
    /**
     * Store a fresh token for the user, valid for `$ttlSeconds`. Every earlier
     * unused token of that user is dropped first: only the newest mail works.
     */
    public function create(int $userId, string $tokenHash, int $ttlSeconds): void;

    /**
     * Mark the token used and return its user id — or null when it is unknown,
     * already used or expired. Single-use is enforced by the UPDATE itself, so
     * two concurrent confirms cannot both succeed.
     */
    public function consume(string $tokenHash): ?int;

    /** Drop every token of the user (after a successful reset). */
    public function deleteForUser(int $userId): void;
}
