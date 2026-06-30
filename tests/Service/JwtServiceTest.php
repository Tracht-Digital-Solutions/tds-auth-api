<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Service;

use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Domain\AppUser;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Tests\Support\Keys;

final class JwtServiceTest extends TestCase
{
    private Keys $keys;
    private JwtService $jwt;

    protected function setUp(): void
    {
        $this->keys = new Keys();
        $this->jwt = new JwtService(
            privateKeyPem: $this->keys->privatePem,
            publicKeyPem: $this->keys->publicPem,
            keyId: 'test-kid',
            issuer: 'tds-auth-api-test',
            ttlSeconds: 900,
            refreshTtlSeconds: 86400,
        );
    }

    public function test_issue_admin_round_trips_through_verify(): void
    {
        $issued = $this->jwt->issueAdmin();

        $claims = $this->jwt->verify($issued['token']);
        self::assertTrue($claims['admin']);
        self::assertNull($claims['customer_id']);
        self::assertSame('tds-auth-api-test', $claims['iss']);
        self::assertSame('admin', $claims['sub']);
        self::assertSame($issued['jti'], $claims['jti']);
        self::assertSame($issued['expiresAt'], $claims['exp']);
    }

    public function test_issue_customer_includes_customer_id(): void
    {
        $issued = $this->jwt->issueCustomer(42);

        $claims = $this->jwt->verify($issued['token']);
        self::assertFalse($claims['admin']);
        self::assertSame(42, $claims['customer_id']);
        self::assertSame('42', $claims['sub']);
    }

    public function test_issue_for_customer_user_carries_uid_and_permissions(): void
    {
        $user = new AppUser(
            id: 99,
            email: 'cust@example.com',
            name: 'Cust',
            isAdmin: false,
            customerId: 7,
            permissions: ['invoices:read', 'invoices:pay'],
            status: 'active',
            passwordHash: 'x',
        );

        $claims = $this->jwt->verify($this->jwt->issueForUser($user)['token']);

        self::assertFalse($claims['admin']);
        self::assertSame(7, $claims['customer_id']);
        self::assertSame(99, $claims['uid']);
        self::assertSame(['invoices:read', 'invoices:pay'], $claims['permissions']);
        self::assertSame('99', $claims['sub']);
    }

    public function test_issue_for_admin_user_omits_permissions(): void
    {
        $user = new AppUser(
            id: 1,
            email: 'admin@example.com',
            name: 'Admin',
            isAdmin: true,
            customerId: null,
            permissions: ['invoices:pay'],
            status: 'active',
            passwordHash: 'x',
        );

        $claims = $this->jwt->verify($this->jwt->issueForUser($user)['token']);

        self::assertTrue($claims['admin']);
        self::assertNull($claims['customer_id']);
        self::assertSame(1, $claims['uid']);
        self::assertSame([], $claims['permissions']);
    }

    public function test_verify_rejects_token_with_wrong_issuer(): void
    {
        $foreign = new JwtService(
            privateKeyPem: $this->keys->privatePem,
            publicKeyPem: $this->keys->publicPem,
            keyId: 'test-kid',
            issuer: 'someone-else',
            ttlSeconds: 900,
            refreshTtlSeconds: 86400,
        );
        $token = $foreign->issueAdmin()['token'];

        $this->expectException(\RuntimeException::class);
        $this->jwt->verify($token);
    }

    public function test_verify_rejects_token_signed_by_other_key(): void
    {
        $otherKeys = new Keys();
        $hostile = JWT::encode(
            [
                'iss' => 'tds-auth-api-test',
                'sub' => 'admin',
                'aud' => 'tds-services',
                'iat' => time(),
                'exp' => time() + 60,
                'jti' => 'spoof',
                'admin' => true,
            ],
            $otherKeys->privatePem,
            'RS256',
            'test-kid',
        );

        $this->expectException(\RuntimeException::class);
        $this->jwt->verify($hostile);
    }

    public function test_verify_rejects_expired_token(): void
    {
        $shortLived = new JwtService(
            privateKeyPem: $this->keys->privatePem,
            publicKeyPem: $this->keys->publicPem,
            keyId: 'test-kid',
            issuer: 'tds-auth-api-test',
            ttlSeconds: -1,
            refreshTtlSeconds: 86400,
        );
        $token = $shortLived->issueAdmin()['token'];

        $this->expectException(\RuntimeException::class);
        $this->jwt->verify($token);
    }

    public function test_key_health_returns_true_for_real_keys(): void
    {
        self::assertTrue($this->jwt->keyHealth());
    }

    public function test_jwk_publishes_kid_alg_kty_and_modulus(): void
    {
        $jwk = $this->jwt->jwk();

        self::assertSame('RSA', $jwk['kty']);
        self::assertSame('RS256', $jwk['alg']);
        self::assertSame('sig', $jwk['use']);
        self::assertSame('test-kid', $jwk['kid']);
        self::assertNotEmpty($jwk['n']);
        self::assertNotEmpty($jwk['e']);
        // n must be base64url with no padding
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $jwk['n']);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $jwk['e']);
    }
}
