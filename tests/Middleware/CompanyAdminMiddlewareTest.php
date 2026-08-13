<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Middleware;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Factory\AppFactory;
use Slim\Psr7\Factory\ServerRequestFactory;
use Tds\AuthApi\Middleware\CompanyAdminMiddleware;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;

/**
 * The gate on `/company/{companyId}/*`.
 *
 * This is the only thing between a company admin and every OTHER company's
 * users, so each case here is a boundary rather than a behaviour: pass for the
 * platform admin, pass for this company's own admin, and refuse everything
 * else — including a principal who administers a DIFFERENT company, which is
 * the interesting one.
 */
final class CompanyAdminMiddlewareTest extends TestCase
{
    private ?int $seenCompanyId = null;

    /**
     * Run the gate through a REAL Slim app.
     *
     * `RouteContext::fromRequest()` needs the full routing state, not a
     * hand-attached route — and going through the router also exercises the
     * LIFO ordering the real wiring depends on, which a hand-built request
     * would quietly skip.
     *
     * @param array<string,mixed> $claims
     */
    private function gate(array $claims, int $companyId): ResponseInterface
    {
        $this->seenCompanyId = null;

        $app = AppFactory::create();
        $app->addRoutingMiddleware();

        $app->get('/company/{companyId:[0-9]+}/users', function ($request, $response) {
            $this->seenCompanyId = $request->getAttribute(CompanyAdminMiddleware::ATTR_COMPANY_ID);
            $response->getBody()->write('ok');

            return $response;
        })
            ->add(new CompanyAdminMiddleware())
            // Stands in for JwtAuthMiddleware: attaches the claims the gate
            // reads. Added last, so it runs FIRST (Slim middleware is LIFO).
            ->add(function ($request, $handler) use ($claims) {
                return $handler->handle(
                    $request->withAttribute(JwtAuthMiddleware::ATTR_CLAIMS, $claims),
                );
            });

        return $app->handle(
            (new ServerRequestFactory())->createServerRequest('GET', "/company/{$companyId}/users"),
        );
    }

    public function test_a_platform_admin_passes_for_any_company(): void
    {
        $response = $this->gate(['admin' => true], 42);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('ok', (string) $response->getBody());
    }

    public function test_the_companys_own_admin_passes(): void
    {
        $claims = ['admin' => false, 'companies' => [
            ['id' => 7, 'permissions' => [], 'admin' => true],
        ]];

        self::assertSame(200, $this->gate($claims, 7)->getStatusCode());
    }

    public function test_an_admin_of_ANOTHER_company_is_refused(): void
    {
        // The case the whole gate exists for.
        $claims = ['admin' => false, 'companies' => [
            ['id' => 7, 'permissions' => [], 'admin' => true],
        ]];

        self::assertSame(403, $this->gate($claims, 9)->getStatusCode());
    }

    public function test_a_plain_member_of_the_company_is_refused(): void
    {
        // Belonging is not administering.
        $claims = ['admin' => false, 'companies' => [
            ['id' => 7, 'permissions' => ['tickets:read'], 'admin' => false],
        ]];

        self::assertSame(403, $this->gate($claims, 7)->getStatusCode());
    }

    public function test_a_membership_without_an_admin_key_is_refused(): void
    {
        // A token minted before the flag existed carries no `admin` key. It
        // must read as false, not as missing-therefore-permitted.
        $claims = ['admin' => false, 'companies' => [['id' => 7, 'permissions' => []]]];

        self::assertSame(403, $this->gate($claims, 7)->getStatusCode());
    }

    public function test_a_principal_with_no_companies_is_refused(): void
    {
        self::assertSame(403, $this->gate(['admin' => false], 7)->getStatusCode());
    }

    public function test_it_normalises_stdClass_companies(): void
    {
        // JWT decode yields stdClass for nested objects; reading it as an array
        // without normalising would silently refuse every real company admin.
        $company = new \stdClass();
        $company->id = 7;
        $company->admin = true;

        self::assertSame(200, $this->gate(['admin' => false, 'companies' => [$company]], 7)->getStatusCode());
    }

    public function test_it_attaches_the_company_id_for_the_action(): void
    {
        $this->gate(['admin' => true], 42);

        self::assertSame(
            42,
            $this->seenCompanyId,
        );
    }
}
