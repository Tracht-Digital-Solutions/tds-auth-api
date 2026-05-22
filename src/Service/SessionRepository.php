<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

interface SessionRepository
{
    public function record(string $jti, ?int $customerId, bool $admin, int $expiresAtUnix): void;

    public function isRevoked(string $jti): bool;

    public function revoke(string $jti): void;

    /**
     * List sessions that haven't been revoked and haven't expired yet.
     * Used by the admin sessions endpoint.
     *
     * @return list<array{
     *   jti: string,
     *   customer_id: ?int,
     *   admin: bool,
     *   expires_at: string,
     *   created_at: string
     * }>
     */
    public function listActive(int $limit = 200): array;
}
