<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action\Customer;

use PDO;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\Customer\LoginAction;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Tests\Support\FakeSessionRepository;
use Tds\AuthApi\Tests\Support\Keys;

/**
 * Integration test: customer login depends on a real PDO connection to
 * look up credentials. Skipped without TDS_TEST_DB_DSN.
 */
final class LoginActionTest extends TestCase
{
    private PDO $pdo;
    private JwtService $jwt;
    private FakeSessionRepository $sessions;
    private CookieFactory $cookies;

    protected function setUp(): void
    {
        $dsn = getenv('TDS_TEST_DB_DSN') ?: '';
        if ($dsn === '') {
            self::markTestSkipped('Set TDS_TEST_DB_DSN to run customer login tests.');
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

    public function test_malformed_payload_returns_400(): void
    {
        $response = $this->login(['email' => 'not-an-email', 'password' => 'whatever']);

        self::assertSame(400, $response->getStatusCode());
    }

    public function test_missing_email_returns_400(): void
    {
        $response = $this->login(['password' => 'whatever']);

        self::assertSame(400, $response->getStatusCode());
    }

    public function test_unknown_email_returns_401_without_timing_leak(): void
    {
        $response = $this->login(['email' => 'ghost@example.com', 'password' => 'whatever']);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(['error' => 'Invalid credentials'], $this->jsonBody($response));
    }

    public function test_wrong_password_returns_401(): void
    {
        $this->seed('user@example.com', 'correct-password', customerId: 7);

        $response = $this->login(['email' => 'user@example.com', 'password' => 'wrong-password']);

        self::assertSame(401, $response->getStatusCode());
    }

    public function test_correct_password_issues_customer_jwt(): void
    {
        $this->seed('user@example.com', 'correct-password', customerId: 7);

        $response = $this->login(['email' => 'user@example.com', 'password' => 'correct-password']);

        self::assertSame(200, $response->getStatusCode());
        $body = $this->jsonBody($response);
        self::assertSame(7, $body['customerId']);
        $claims = $this->jwt->verify($body['token']);
        self::assertSame(7, $claims['customer_id']);
        self::assertFalse($claims['admin']);
    }

    public function test_email_lookup_is_case_insensitive(): void
    {
        $this->seed('user@example.com', 'correct-password', customerId: 7);

        $response = $this->login(['email' => 'USER@example.com', 'password' => 'correct-password']);

        self::assertSame(200, $response->getStatusCode());
    }

    private function seed(string $email, string $password, int $customerId): void
    {
        $hash = password_hash($password, PASSWORD_ARGON2ID);
        $stmt = $this->pdo->prepare(
            'INSERT INTO customer_credential (customer_id, email, password_hash) VALUES (?, ?, ?)'
        );
        $stmt->execute([$customerId, $email, $hash]);
    }

    /** @param array<string,mixed> $payload */
    private function login(array $payload): ResponseInterface
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('POST', '/customer/login')
            ->withParsedBody($payload);
        $action = new LoginAction($this->pdo, $this->jwt, $this->sessions, $this->cookies);
        return $action($request, new Response());
    }

    /** @return array<string,mixed> */
    private function jsonBody(ResponseInterface $response): array
    {
        $response->getBody()->rewind();
        return json_decode($response->getBody()->getContents(), true);
    }
}
