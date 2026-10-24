<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

/**
 * One-time confirmation tokens of self-registered accounts, stored as SHA-256
 * hashes only. Each token carries the password hash and name of its own
 * registration request (see the AuthAccountConfirm migration for why).
 */
interface AccountConfirmRepository
{
    /**
     * Store a fresh token for the pending user, valid for `$ttlSeconds`. Earlier
     * tokens of that user stay valid: they belong to other registration
     * requests, and only the mailbox owner can click any of them.
     */
    public function create(int $userId, string $tokenHash, string $passwordHash, ?string $name, int $ttlSeconds): void;

    /**
     * Mark the token used and return what its registration asked for — or null
     * when it is unknown, already used or expired. Single-use is enforced by
     * the UPDATE itself.
     *
     * @return array{userId:int, passwordHash:string, name:?string}|null
     */
    public function consume(string $tokenHash): ?array;

    /** Drop every token of the user (after a successful confirmation). */
    public function deleteForUser(int $userId): void;
}
