<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

interface SessionRepository
{
    public function record(string $jti, ?int $companyId, bool $admin, int $expiresAtUnix, ?int $userId = null): void;

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
     *   company_id: ?int,
     *   customer_id: ?int,
     *   admin: bool,
     *   expires_at: string,
     *   created_at: string
     * }>
     */
    public function listActive(int $limit = 200): array;

    /**
     * The same list, restricted to ONE user — what the profile page's
     * "aktive Sitzungen" shows. Separate from {@see self::listActive()}
     * because that one neither selects nor filters `user_id`: a self-service
     * caller filtering the admin list in PHP would have to be handed every
     * other user's sessions first.
     *
     * @return list<array{
     *   jti: string,
     *   company_id: ?int,
     *   customer_id: ?int,
     *   admin: bool,
     *   expires_at: string,
     *   created_at: string
     * }>
     */
    public function listActiveForUser(int $userId, int $limit = 50): array;

    /**
     * Who a session belongs to, or null when it does not exist / is already
     * revoked or expired.
     *
     * Exists so a self-service revoke can prove ownership BEFORE calling
     * {@see self::revoke()}, which happily revokes any jti it is given.
     */
    public function ownerOf(string $jti): ?int;
}
