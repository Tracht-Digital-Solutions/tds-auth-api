<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

interface SessionRepository
{
    public function record(string $jti, ?int $customerId, bool $admin, int $expiresAtUnix): void;

    public function isRevoked(string $jti): bool;

    public function revoke(string $jti): void;
}
