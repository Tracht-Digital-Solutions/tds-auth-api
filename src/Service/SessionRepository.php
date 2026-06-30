<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

interface SessionRepository
{
    public function record(string $jti, ?int $customerId, bool $admin, int $expiresAtUnix, ?int $userId = null): void;

    public function isRevoked(string $jti): bool;

    public function revoke(string $jti): void;

    /**
     * Revoke every still-active session belonging to a user. Used when an
     * admin disables/deletes a user, resets their password, or changes their
     * admin flag / permissions — forcing a fresh login with current claims.
     */
    public function revokeAllForUser(int $userId): void;

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
