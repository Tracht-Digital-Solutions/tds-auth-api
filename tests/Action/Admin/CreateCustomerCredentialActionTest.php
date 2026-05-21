<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action\Admin;

use PDO;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\Admin\CreateCustomerCredentialAction;

final class CreateCustomerCredentialActionTest extends TestCase
{
    private PDO $pdo;

    protected function setUp(): void
    {
        $dsn = getenv('TDS_TEST_DB_DSN') ?: '';
        if ($dsn === '') {
            self::markTestSkipped('Set TDS_TEST_DB_DSN to run credential creation tests.');
        }

        $this->pdo = new PDO(
            $dsn,
            getenv('TDS_TEST_DB_USER') ?: null,
            getenv('TDS_TEST_DB_PASS') ?: null,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
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
              UNIQUE KEY uniq_email (email)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        SQL);
    }

    public function test_non_array_body_returns_400(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest('POST', '/admin/customer-credentials');
        $response = (new CreateCustomerCredentialAction($this->pdo))($request, new Response());

        self::assertSame(400, $response->getStatusCode());
    }

    public function test_invalid_customer_id_returns_422(): void
    {
        $response = $this->post([
            'customer_id' => 0,
            'email' => 'user@example.com',
            'password' => 'sixteen-char-pwd',
        ]);

        self::assertSame(422, $response->getStatusCode());
    }

    public function test_invalid_email_returns_422(): void
    {
        $response = $this->post([
            'customer_id' => 1,
            'email' => 'not-an-email',
            'password' => 'sixteen-char-pwd',
        ]);

        self::assertSame(422, $response->getStatusCode());
    }

    public function test_short_password_returns_422(): void
    {
        $response = $this->post([
            'customer_id' => 1,
            'email' => 'user@example.com',
            'password' => 'too-short',
        ]);

        self::assertSame(422, $response->getStatusCode());
    }

    public function test_happy_path_returns_201_and_persists(): void
    {
        $response = $this->post([
            'customer_id' => 1,
            'email' => 'user@example.com',
            'password' => 'sixteen-char-pwd',
        ]);

        self::assertSame(201, $response->getStatusCode());
        $count = (int) $this->pdo->query("SELECT COUNT(*) FROM customer_credential WHERE email = 'user@example.com'")
            ->fetchColumn();
        self::assertSame(1, $count);
    }

    public function test_duplicate_email_returns_409(): void
    {
        $first = $this->post([
            'customer_id' => 1,
            'email' => 'user@example.com',
            'password' => 'sixteen-char-pwd',
        ]);
        self::assertSame(201, $first->getStatusCode());

        $second = $this->post([
            'customer_id' => 2,
            'email' => 'user@example.com',
            'password' => 'sixteen-char-pwd',
        ]);

        self::assertSame(409, $second->getStatusCode());
    }

    /** @param array<string,mixed> $payload */
    private function post(array $payload): ResponseInterface
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('POST', '/admin/customer-credentials')
            ->withParsedBody($payload);
        return (new CreateCustomerCredentialAction($this->pdo))($request, new Response());
    }
}
