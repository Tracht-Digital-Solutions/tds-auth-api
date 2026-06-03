<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action\Customer;

use PDO;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\Customer\ChangePasswordAction;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Tests\Support\FakeSessionRepository;
use Tds\AuthApi\Tests\Support\Keys;

/**
 * Integration test: reads/writes customer_credential. Skipped without
 * TDS_TEST_DB_DSN.
 */
final class ChangePasswordActionTest extends TestCase
{
    private PDO $pdo;
    private JwtService $jwt;
    private FakeSessionRepository $sessions;
    private CookieFactory $cookies;

    protected function setUp(): void
    {
        $dsn = getenv('TDS_TEST_DB_DSN') ?: '';
        if ($dsn === '') {
            self::markTestSkipped('Set TDS_TEST_DB_DSN to run change-password tests.');
        }

        $this->pdo = new PDO(
            $dsn,
            getenv('TDS_TEST_DB_USER') ?: null,
            getenv('TDS_TEST_DB_PASS') ?: null,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ],
        );

        $this->pdo->exec('DROP TABLE IF EXISTS customer_credential');
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE customer_credential (
              id INT UNSIGNED NOT NULL AUTO_INCREMENT,
              customer_id INT NOT NULL,
              email VARCHAR(254) NOT NULL,
              password_hash VARCHAR(255) NOT NULL,
              created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
              PRIMARY KEY (id),
              UNIQUE KEY uniq_email (email),
              KEY idx_customer_id (customer_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        SQL);

        $keys = new Keys();
        $this->jwt = new JwtService(
            privateKeyPem: $keys->privatePem,
            publicKeyPem: $keys->publicPem,
            keyId: 'kid',
            issuer: 'tds-auth-api-test',
            ttlSeconds: 900,
            refreshTtlSeconds: 86400,
        );
        $this->sessions = new FakeSessionRepository();
        $this->cookies = new CookieFactory('tds_session', '.local', secure: false);
    }

    public function test_missing_token_returns_401(): void
    {
        $response = $this->changePassword(token: null, payload: ['old' => 'old-password-1', 'new' => 'new-password-1']);

        self::assertSame(401, $response->getStatusCode());
    }

    public function test_admin_token_is_rejected(): void
    {
        $issued = $this->jwt->issueAdmin();
        $this->sessions->record($issued['jti'], null, true, $issued['expiresAt']);

        $response = $this->changePassword(token: $issued['token'], payload: ['old' => 'old-password-1', 'new' => 'new-password-1']);

        self::assertSame(403, $response->getStatusCode());
    }

    public function test_revoked_session_returns_401(): void
    {
        $this->seed(7, 'old-password-1');
        $issued = $this->liveCustomer(7);
        $this->sessions->revoke($issued['jti']);

        $response = $this->changePassword(token: $issued['token'], payload: ['old' => 'old-password-1', 'new' => 'new-password-2']);

        self::assertSame(401, $response->getStatusCode());
    }

    public function test_missing_body_fields_return_400(): void
    {
        $issued = $this->liveCustomer(7);

        $response = $this->changePassword(token: $issued['token'], payload: ['old' => 'old-password-1']);

        self::assertSame(400, $response->getStatusCode());
    }

    public function test_short_new_password_returns_422(): void
    {
        $this->seed(7, 'old-password-1');
        $issued = $this->liveCustomer(7);

        $response = $this->changePassword(token: $issued['token'], payload: ['old' => 'old-password-1', 'new' => 'short']);

        self::assertSame(422, $response->getStatusCode());
    }

    public function test_reused_password_returns_422(): void
    {
        $this->seed(7, 'old-password-1');
        $issued = $this->liveCustomer(7);

        $response = $this->changePassword(token: $issued['token'], payload: ['old' => 'old-password-1', 'new' => 'old-password-1']);

        self::assertSame(422, $response->getStatusCode());
    }

    public function test_wrong_old_password_returns_401(): void
    {
        $this->seed(7, 'old-password-1');
        $issued = $this->liveCustomer(7);

        $response = $this->changePassword(token: $issued['token'], payload: ['old' => 'wrong-password-x', 'new' => 'new-password-1']);

        self::assertSame(401, $response->getStatusCode());
    }

    public function test_happy_path_rotates_hash_and_revokes_old_jti(): void
    {
        $this->seed(7, 'old-password-1');
        $issued = $this->liveCustomer(7);
        $oldJti = $issued['jti'];

        $response = $this->changePassword(token: $issued['token'], payload: ['old' => 'old-password-1', 'new' => 'new-password-2']);

        self::assertSame(200, $response->getStatusCode());
        $body = $this->jsonBody($response);
        self::assertSame(7, $body['customerId']);
        self::assertNotSame($issued['token'], $body['token']);

        $newClaims = $this->jwt->verify($body['token']);
        self::assertSame(7, $newClaims['customer_id']);
        self::assertNotSame($oldJti, $newClaims['jti']);
        self::assertTrue($this->sessions->isRevoked($oldJti), 'old jti must be revoked');

        $row = $this->pdo->query('SELECT password_hash FROM customer_credential WHERE customer_id = 7')->fetch();
        self::assertTrue(password_verify('new-password-2', $row['password_hash']));
        self::assertFalse(password_verify('old-password-1', $row['password_hash']));
    }

    public function test_missing_credential_row_revokes_and_clears_cookie(): void
    {
        $issued = $this->liveCustomer(99);

        $response = $this->changePassword(token: $issued['token'], payload: ['old' => 'old-password-1', 'new' => 'new-password-2']);

        self::assertSame(401, $response->getStatusCode());
        self::assertTrue($this->sessions->isRevoked($issued['jti']));
        self::assertStringContainsString('Max-Age=0', $response->getHeaderLine('Set-Cookie'));
    }

    /**
     * Mint a customer JWT and register its jti as a live session.
     *
     * @return array{token:string,jti:string,expiresAt:int}
     */
    private function liveCustomer(int $customerId): array
    {
        $issued = $this->jwt->issueCustomer($customerId);
        $this->sessions->record($issued['jti'], $customerId, false, $issued['expiresAt']);
        return $issued;
    }

    private function seed(int $customerId, string $password): void
    {
        $hash = password_hash($password, PASSWORD_ARGON2ID);
        $stmt = $this->pdo->prepare(
            'INSERT INTO customer_credential (customer_id, email, password_hash) VALUES (?, ?, ?)'
        );
        $stmt->execute([$customerId, "user{$customerId}@example.com", $hash]);
    }

    /** @param array<string,mixed> $payload */
    private function changePassword(?string $token, array $payload): ResponseInterface
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('PUT', '/customer/password')
            ->withParsedBody($payload);
        if ($token !== null) {
            $request = $request->withHeader('Authorization', 'Bearer ' . $token);
        }
        $action = new ChangePasswordAction(
            $this->pdo,
            $this->jwt,
            $this->sessions,
            $this->cookies,
        );
        return $action($request, new Response());
    }

    /** @return array<string,mixed> */
    private function jsonBody(ResponseInterface $response): array
    {
        $response->getBody()->rewind();
        return json_decode($response->getBody()->getContents(), true);
    }
}
