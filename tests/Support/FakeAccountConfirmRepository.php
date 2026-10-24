<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Support;

use Tds\AuthApi\Service\AccountConfirmRepository;

final class FakeAccountConfirmRepository implements AccountConfirmRepository
{
    /** @var array<string, array{userId:int, passwordHash:string, name:?string, used:bool}> keyed by token hash */
    public array $tokens = [];

    public function create(int $userId, string $tokenHash, string $passwordHash, ?string $name, int $ttlSeconds): void
    {
        $this->tokens[$tokenHash] = ['userId' => $userId, 'passwordHash' => $passwordHash, 'name' => $name, 'used' => false];
    }

    public function consume(string $tokenHash): ?array
    {
        $row = $this->tokens[$tokenHash] ?? null;
        if ($row === null || $row['used']) {
            return null;
        }
        $this->tokens[$tokenHash]['used'] = true;
        return ['userId' => $row['userId'], 'passwordHash' => $row['passwordHash'], 'name' => $row['name']];
    }

    public function deleteForUser(int $userId): void
    {
        $this->tokens = array_filter($this->tokens, static fn (array $row): bool => $row['userId'] !== $userId);
    }
}
