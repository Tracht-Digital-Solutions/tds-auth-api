<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Ramsey\Uuid\Uuid;

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
 *   customer_id?: int|null
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
     * `customer_id`.
     *
     * @return array{token: string, jti: string, expiresAt: int}
     */
    public function issueAdmin(): array
    {
        return $this->issue(['admin' => true, 'customer_id' => null], 'admin');
    }

    /**
     * Issue a customer JWT.
     *
     * @return array{token: string, jti: string, expiresAt: int}
     */
    public function issueCustomer(int $customerId): array
    {
        return $this->issue(['admin' => false, 'customer_id' => $customerId], (string) $customerId);
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
     * @param array{admin:bool, customer_id:int|null} $extra
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
