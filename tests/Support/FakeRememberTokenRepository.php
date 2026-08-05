<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Support;

use Tds\AuthApi\Service\RememberTokenRepository;

/**
 * In-memory remember-me store. The rotation and constant-time rules in
 * RememberTokenService are the part worth testing, and none of them need a
 * database.
 */
final class FakeRememberTokenRepository implements RememberTokenRepository
{
    /** @var array<string, array{user_id:int, validator_hash:string, expires_at:int, user_agent:?string}> */
    public array $rows = [];

    /** Selectors deleted, in order — how rotation is observed. */
    public array $deleted = [];

    public function store(int $userId, string $selector, string $validatorHash, int $expiresAtUnix, ?string $userAgent): void
    {
        $this->rows[$selector] = [
            'user_id' => $userId,
            'validator_hash' => $validatorHash,
            'expires_at' => $expiresAtUnix,
            'user_agent' => $userAgent,
        ];
    }

    public function findBySelector(string $selector): ?array
    {
        $row = $this->rows[$selector] ?? null;
        if ($row === null) {
            return null;
        }
        return [
            'user_id' => $row['user_id'],
            'validator_hash' => $row['validator_hash'],
            'expires_at' => $row['expires_at'],
        ];
    }

    public function deleteBySelector(string $selector): void
    {
        $this->deleted[] = $selector;
        unset($this->rows[$selector]);
    }

    public function deleteForUser(int $userId): void
    {
        foreach ($this->rows as $selector => $row) {
            if ($row['user_id'] === $userId) {
                $this->deleted[] = $selector;
                unset($this->rows[$selector]);
            }
        }
    }

    public function purgeExpired(): void
    {
        foreach ($this->rows as $selector => $row) {
            if ($row['expires_at'] < time()) {
                unset($this->rows[$selector]);
            }
        }
    }
}
