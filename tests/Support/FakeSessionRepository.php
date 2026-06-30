<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Support;

use Tds\AuthApi\Service\SessionRepository;

final class FakeSessionRepository implements SessionRepository
{
    /** @var array<string, array{customer_id:?int, user_id:?int, admin:bool, expires_at:int, revoked:bool}> */
    public array $sessions = [];

    /** @var list<string> */
    public array $revoked = [];

    /** @var list<int> */
    public array $revokedUsers = [];

    public bool $defaultRevokedForUnknown = false;

    public function record(string $jti, ?int $customerId, bool $admin, int $expiresAtUnix, ?int $userId = null): void
    {
        $this->sessions[$jti] = [
            'customer_id' => $customerId,
            'user_id' => $userId,
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

    public function revokeAllForUser(int $userId): void
    {
        $this->revokedUsers[] = $userId;
        foreach ($this->sessions as $jti => $data) {
            if ($data['user_id'] === $userId) {
                $this->sessions[$jti]['revoked'] = true;
            }
        }
    }

    public function listActive(int $limit = 200): array
    {
        $now = time();
        $rows = [];
        foreach ($this->sessions as $jti => $data) {
            if ($data['revoked']) continue;
            if ($data['expires_at'] <= $now) continue;
            $rows[] = [
                'jti' => $jti,
                'customer_id' => $data['customer_id'],
                'admin' => $data['admin'],
                'expires_at' => date('Y-m-d H:i:s', $data['expires_at']),
                'created_at' => date('Y-m-d H:i:s'),
            ];
        }
        return array_slice($rows, 0, $limit);
    }
}
