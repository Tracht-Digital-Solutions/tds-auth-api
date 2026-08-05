<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

/**
 * Storage for "angemeldet bleiben" tokens. Split out from
 * {@see RememberTokenService} so the crypto/rotation rules can be tested
 * without a database.
 */
interface RememberTokenRepository
{
    public function store(int $userId, string $selector, string $validatorHash, int $expiresAtUnix, ?string $userAgent): void;

    /**
     * @return array{user_id:int, validator_hash:string, expires_at:int}|null
     */
    public function findBySelector(string $selector): ?array;

    public function deleteBySelector(string $selector): void;

    public function deleteForUser(int $userId): void;

    /** Housekeeping: drop rows past their expiry. */
    public function purgeExpired(): void;
}
