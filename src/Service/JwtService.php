<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Ramsey\Uuid\Uuid;
use Tds\AuthApi\Domain\AppUser;
use Tds\AuthApi\Domain\Membership;

/**
 * RS256 JWT issuance + verification. Other services verify against
 * the JWKS at /.well-known/jwks.json without ever seeing the
 * private key.
 *
 * @phpstan-type JwtClaims array{
 *   iss: string,
 *   sub: string,
 *   aud: string,
 *   iat: int,
 *   exp: int,
 *   jti: string,
 *   admin: bool,
 *   support_agent?: bool,
 *   customer_id?: int|null,
 *   uid?: int|null,
 *   permissions?: list<string>,
 *   companies?: list<array{id:int, permissions:list<string>}>
 * }
 */
final class JwtService
{
    public function __construct(
        private readonly string $privateKeyPem,
        private readonly string $publicKeyPem,
        private readonly string $keyId,
        private readonly string $issuer,
        private readonly int $ttlSeconds,
        private readonly int $refreshTtlSeconds,
    ) {
    }

    /**
     * Issue an admin JWT. The token has `admin=true` and no
     * `customer_id`. Kept for tests / the refresh fallback path.
     *
     * @return array{token: string, jti: string, expiresAt: int}
     */
    public function issueAdmin(): array
    {
        return $this->issuePrincipal(true, null, null, []);
    }

    /**
     * Issue a customer JWT. Kept for tests / the refresh fallback path.
     *
     * @return array{token: string, jti: string, expiresAt: int}
     */
    public function issueCustomer(int $customerId): array
    {
        return $this->issuePrincipal(false, $customerId, null, []);
    }

    /**
     * Issue a JWT for a unified user. Admins carry no portal permissions
     * (they bypass permission checks downstream).
     *
     * @return array{token: string, jti: string, expiresAt: int}
     */
    public function issueForUser(AppUser $user): array
    {
        // Non-admins carry their company memberships (id + per-company perms);
        // the flat customer_id/permissions claims mirror the primary company for
        // backward compatibility. Admins bypass permissions, so they carry none.
        $companies = $user->isAdmin
            ? []
            : array_map(
                static fn (Membership $m): array => ['id' => $m->customerId, 'permissions' => $m->permissions],
                $user->memberships,
            );

        return $this->issuePrincipal(
            $user->isAdmin,
            $user->customerId,
            $user->id,
            $user->isAdmin ? [] : $user->permissions,
            $user->isAdmin && $user->isSupportAgent,
            $companies,
        );
    }

    /**
     * Issue a JWT for an arbitrary principal. Used by login (via
     * issueForUser) and by refresh, which carries the existing claims
     * forward without a DB lookup.
     *
     * @param list<string> $permissions
     * @param list<array{id:int, permissions:list<string>}> $companies
     * @return array{token: string, jti: string, expiresAt: int}
     */
    public function issuePrincipal(bool $admin, ?int $customerId, ?int $uid, array $permissions, bool $supportAgent = false, array $companies = []): array
    {
        $subject = $uid !== null
            ? (string) $uid
            : ($admin ? 'admin' : (string) ($customerId ?? '0'));

        return $this->issue([
            'admin' => $admin,
            'support_agent' => $supportAgent,
            'customer_id' => $customerId,
            'uid' => $uid,
            'permissions' => array_values($permissions),
            'companies' => array_values($companies),
        ], $subject);
    }

    /**
     * Verify a token and return its claims.
     *
     * @return array<string, mixed>
     * @throws \RuntimeException on any verification failure
     */
    public function verify(string $token): array
    {
        try {
            $decoded = JWT::decode($token, new Key($this->publicKeyPem, 'RS256'));
        } catch (\Throwable $e) {
            throw new \RuntimeException('JWT verify failed: ' . $e->getMessage(), 0, $e);
        }
        $claims = (array) $decoded;
        if (($claims['iss'] ?? null) !== $this->issuer) {
            throw new \RuntimeException('JWT iss mismatch');
        }
        return $claims;
    }

    /**
     * Cheap self-check for /healthz — confirms the configured
     * private key parses as a usable RSA key. Doesn't actually sign
     * (that needs a real subject and produces a token we'd just
     * throw away).
     */
    public function keyHealth(): bool
    {
        try {
            return openssl_pkey_get_private($this->privateKeyPem) !== false;
        } catch (\Throwable) {
            return false;
        }
    }

    public function refreshTtl(): int
    {
        return $this->refreshTtlSeconds;
    }

    public function ttl(): int
    {
        return $this->ttlSeconds;
    }

    /** @return array{kid:string, alg:string, kty:string, use:string, n:string, e:string} */
    public function jwk(): array
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_public($this->publicKeyPem) ?: throw new \RuntimeException('invalid public key'));
        if ($details === false || !isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new \RuntimeException('Could not extract RSA modulus/exponent from public key');
        }
        return [
            'kty' => 'RSA',
            'alg' => 'RS256',
            'use' => 'sig',
            'kid' => $this->keyId,
            'n' => self::base64Url($details['rsa']['n']),
            'e' => self::base64Url($details['rsa']['e']),
        ];
    }

    /**
     * @param array{admin:bool, support_agent:bool, customer_id:int|null, uid:int|null, permissions:list<string>, companies:list<array{id:int, permissions:list<string>}>} $extra
     * @return array{token: string, jti: string, expiresAt: int}
     */
    private function issue(array $extra, string $subject): array
    {
        $now = time();
        $exp = $now + $this->ttlSeconds;
        $jti = Uuid::uuid4()->toString();

        $payload = array_merge([
            'iss' => $this->issuer,
            'sub' => $subject,
            'aud' => 'tds-services',
            'iat' => $now,
            'exp' => $exp,
            'jti' => $jti,
        ], $extra);

        $token = JWT::encode($payload, $this->privateKeyPem, 'RS256', $this->keyId);
        return ['token' => $token, 'jti' => $jti, 'expiresAt' => $exp];
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
