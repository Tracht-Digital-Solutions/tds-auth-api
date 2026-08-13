<?php
declare(strict_types=1);

namespace Tds\AuthApi\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;
use Slim\Routing\RouteContext;

/**
 * Gate for the `/company/{companyId}/*` surface: may this principal manage
 * THIS company?
 *
 * Runs after {@see JwtAuthMiddleware} (Slim middleware is LIFO, so it is added
 * BEFORE it on the route) and reads the claims that one attached. Passes for:
 *
 * - a **platform admin** (`admin: true`) — they manage everything; and
 * - a principal whose `companies` claim contains this company with
 *   `admin: true` — the delegated company admin.
 *
 * ### The company comes from the PATH, not a header
 *
 * `X-Act-As-Customer` would have worked too, and was rejected for two reasons:
 * auth-api's CORS allow-list does not include it (so every call would fail its
 * preflight, and the fix would be to widen the allow-list of the service that
 * holds the keypair), and a company id inferred from ambient state does not
 * appear in the access log. A destructive route should say out loud which
 * tenant it acted on.
 *
 * ### The signed claim is trusted
 *
 * No database read here. Every change to `is_company_admin` revokes that user's
 * sessions, so a demoted admin's next request has no valid token at all — the
 * established propagation model in this service, and the reason the claim can
 * be believed for the hour it lives.
 */
final class CompanyAdminMiddleware implements MiddlewareInterface
{
    /**
     * Namespaced on purpose.
     *
     * Slim publishes each route argument as a request attribute under its own
     * name, so a plain `companyId` here is silently OVERWRITTEN by the route's
     * raw string before the action ever reads it — and `(int) "7"` still
     * happens to work, which is exactly why this would have gone unnoticed
     * until an action did something an int and a string disagree about.
     */
    public const ATTR_COMPANY_ID = 'tds.companyId';

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        /** @var array<string,mixed> $claims */
        $claims = (array) $request->getAttribute(JwtAuthMiddleware::ATTR_CLAIMS, []);

        $route = RouteContext::fromRequest($request)->getRoute();
        $companyId = (int) ($route?->getArgument('companyId') ?? 0);

        if ($companyId <= 0) {
            return $this->error(404, 'Company not found');
        }

        if ((bool) ($claims['admin'] ?? false) === true) {
            return $handler->handle($request->withAttribute(self::ATTR_COMPANY_ID, $companyId));
        }

        if (!self::administers($claims, $companyId)) {
            // 403 rather than 404: the caller is authenticated and the company
            // id came from their own URL, so nothing is disclosed by admitting
            // they may not manage it. (Contrast the per-USER routes, where 404
            // is used precisely to avoid confirming an account exists.)
            return $this->error(403, 'Company administration required');
        }

        return $handler->handle($request->withAttribute(self::ATTR_COMPANY_ID, $companyId));
    }

    /** @param array<string,mixed> $claims */
    private static function administers(array $claims, int $companyId): bool
    {
        $raw = $claims['companies'] ?? null;
        if ($raw === null) {
            return false;
        }
        // JWT decode yields stdClass for nested objects — normalise to arrays.
        $companies = json_decode((string) json_encode($raw), true);
        if (!is_array($companies)) {
            return false;
        }

        foreach ($companies as $company) {
            if (!is_array($company)) {
                continue;
            }
            if ((int) ($company['id'] ?? 0) === $companyId && (bool) ($company['admin'] ?? false)) {
                return true;
            }
        }

        return false;
    }

    private function error(int $status, string $message): ResponseInterface
    {
        $response = new Response();
        $response->getBody()->write(json_encode(['error' => $message]));

        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
