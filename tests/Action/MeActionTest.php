<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\MeAction;
use Tds\AuthApi\Domain\AppUser;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Tests\Support\FakeAppUserRepository;

final class MeActionTest extends TestCase
{
    private FakeAppUserRepository $users;

    protected function setUp(): void
    {
        $this->users = new FakeAppUserRepository();
    }

    public function test_returns_customer_principal(): void
    {
        $this->users->seed(new AppUser(3, 'cust@example.com', 'Cust', false, 7, ['invoices:read'], 'active', 'x'));

        $response = $this->me(['uid' => 3]);

        self::assertSame(200, $response->getStatusCode());
        $body = $this->jsonBody($response);
        self::assertSame(3, $body['userId']);
        self::assertFalse($body['isAdmin']);
        self::assertSame(7, $body['customerId']);
        self::assertSame(['invoices:read'], $body['permissions']);
    }

    public function test_admin_principal_has_empty_permissions(): void
    {
        $this->users->seed(new AppUser(1, 'admin@example.com', 'Admin', true, null, [], 'active', 'x'));

        $body = $this->jsonBody($this->me(['uid' => 1]));

        self::assertTrue($body['isAdmin']);
        self::assertSame([], $body['permissions']);
    }

    public function test_unknown_user_returns_401(): void
    {
        self::assertSame(401, $this->me(['uid' => 999])->getStatusCode());
    }

    /** @param array<string,mixed> $claims */
    private function me(array $claims): ResponseInterface
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', '/me')
            ->withAttribute(JwtAuthMiddleware::ATTR_CLAIMS, $claims);
        return (new MeAction($this->users))($request, new Response());
    }

    /** @return array<string,mixed> */
    private function jsonBody(ResponseInterface $response): array
    {
        $response->getBody()->rewind();
        return json_decode($response->getBody()->getContents(), true);
    }
}
