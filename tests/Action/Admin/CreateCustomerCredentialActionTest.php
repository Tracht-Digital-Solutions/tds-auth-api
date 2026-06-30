<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action\Admin;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\Admin\CreateCustomerCredentialAction;
use Tds\AuthApi\Tests\Support\FakeAppUserRepository;

final class CreateCustomerCredentialActionTest extends TestCase
{
    private FakeAppUserRepository $users;

    protected function setUp(): void
    {
        $this->users = new FakeAppUserRepository();
    }

    public function test_non_array_body_returns_400(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest('POST', '/admin/customer-credentials');
        $response = (new CreateCustomerCredentialAction($this->users))($request, new Response());

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

    public function test_happy_path_returns_201_and_creates_customer_user(): void
    {
        $response = $this->post([
            'customer_id' => 5,
            'email' => 'user@example.com',
            'password' => 'sixteen-char-pwd',
        ]);

        self::assertSame(201, $response->getStatusCode());
        $user = $this->users->findByEmail('user@example.com');
        self::assertNotNull($user);
        self::assertFalse($user->isAdmin);
        self::assertSame(5, $user->customerId);
        // Default onboarding grants full portal access.
        self::assertContains('invoices:pay', $user->permissions);
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
        return (new CreateCustomerCredentialAction($this->users))($request, new Response());
    }
}
