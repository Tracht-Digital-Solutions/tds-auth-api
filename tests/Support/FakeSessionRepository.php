<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Support;

use Tds\AuthApi\Service\SessionRepository;

final class FakeSessionRepository implements SessionRepository
{
    /** @var array<string, array{customer_id:?int, admin:bool, expires_at:int, revoked:bool}> */
    public array $sessions = [];

    /** @var list<string> */
    public array $revoked = [];

    public bool $defaultRevokedForUnknown = false;

    public function record(string $jti, ?int $customerId, bool $admin, int $expiresAtUnix): void
    {
        $this->sessions[$jti] = [
            'customer_id' => $customerId,
            'admin' => $admin,
            'expires_at' => $expiresAtUnix,
            'revoked' => false,
        ];
    }

    public function isRevoked(string $jti): bool
    {
        if (!isset($this->sessions[$jti])) {
            return $this->defaultRevokedForUnknown;
        }
        return $this->sessions[$jti]['revoked'];
    }

    public function revoke(string $jti): void
    {
        $this->revoked[] = $jti;
        if (isset($this->sessions[$jti])) {
            $this->sessions[$jti]['revoked'] = true;
        }
    }
}
