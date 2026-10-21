<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Support;

use Tds\AuthApi\Service\PasswordResetRepository;

/** In-memory reset tokens; `expire()` stands in for the clock. */
final class FakePasswordResetRepository implements PasswordResetRepository
{
    /** @var array<string, array{userId:int, used:bool, expired:bool}> */
    public array $tokens = [];

    public function create(int $userId, string $tokenHash, int $ttlSeconds): void
    {
        $this->deleteForUser($userId);
        $this->tokens[$tokenHash] = ['userId' => $userId, 'used' => false, 'expired' => false];
    }

    public function consume(string $tokenHash): ?int
    {
        $row = $this->tokens[$tokenHash] ?? null;
        if ($row === null || $row['used'] || $row['expired']) {
            return null;
        }
        $this->tokens[$tokenHash]['used'] = true;
        return $row['userId'];
    }

    public function deleteForUser(int $userId): void
    {
        $this->tokens = array_filter($this->tokens, static fn (array $r): bool => $r['userId'] !== $userId);
    }

    public function expire(string $tokenHash): void
    {
        $this->tokens[$tokenHash]['expired'] = true;
    }
}
