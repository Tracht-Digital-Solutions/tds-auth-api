<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Service\SessionRepository;

/**
 * POST /refresh
 *
 * Accepts an existing (still-valid OR recently-expired) JWT, verifies
 * the original signature and that the session row hasn't been
 * revoked, then issues a fresh JWT with a new expiry. The old jti
 * stays valid until its natural exp; revocation only happens on
 * explicit logout.
 */
final class RefreshAction
{
    public function __construct(
        private readonly JwtService $jwt,
        private readonly SessionRepository $sessions,
        private readonly CookieFactory $cookies,
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $token = $this->extractToken($request);
        if ($token === null) {
            return $this->json($response, 401, ['error' => 'No token presented']);
        }

        try {
            $claims = $this->jwt->verify($token);
        } catch (\Throwable) {
            return $this->json($response, 401, ['error' => 'Invalid token']);
        }

        $jti = (string) ($claims['jti'] ?? '');
        if ($jti === '' || $this->sessions->isRevoked($jti)) {
            return $this->json($response, 401, ['error' => 'Session revoked']);
        }

        $admin = (bool) ($claims['admin'] ?? false);
        $supportAgent = (bool) ($claims['support_agent'] ?? false);
        $blogAuthor = (bool) ($claims['blog_author'] ?? false);
        $customerId = isset($claims['customer_id']) && is_int($claims['customer_id']) ? $claims['customer_id'] : null;
        $uid = isset($claims['uid']) && is_int($claims['uid']) ? $claims['uid'] : null;
        $permissions = isset($claims['permissions']) && is_array($claims['permissions'])
            ? array_values(array_map('strval', $claims['permissions']))
            : [];
        $companies = isset($claims['companies']) && is_array($claims['companies'])
            ? $this->normaliseCompanies($claims['companies'])
            : [];

        if (!$admin && $customerId === null) {
            throw new \RuntimeException('non-admin without customer_id');
        }

        // Carry the principal forward without a DB lookup. Authorization
        // changes take effect via session revocation (see UpdateUserAction),
        // which forces a fresh login rather than relying on refresh.
        $issued = $this->jwt->issuePrincipal($admin, $customerId, $uid, $permissions, $supportAgent, $companies, $blogAuthor);

        $this->sessions->record($issued['jti'], $customerId, $admin, $issued['expiresAt'], $uid);

        $response = $this->json($response, 200, [
            'token' => $issued['token'],
            'expiresAt' => $issued['expiresAt'],
        ]);
        return $response->withHeader('Set-Cookie', $this->cookies->set($issued['token'], $this->jwt->ttl()));
    }

    /**
     * Coerce the decoded `companies` claim (each entry may be an array or a
     * stdClass after JWT decode) into the shape issuePrincipal expects.
     *
     * @param array<int,mixed> $raw
     * @return list<array{id:int, permissions:list<string>}>
     */
    private function normaliseCompanies(array $raw): array
    {
        $out = [];
        foreach ($raw as $entry) {
            $e = (array) $entry;
            $id = isset($e['id']) ? (int) $e['id'] : 0;
            if ($id <= 0) {
                continue;
            }
            $perms = isset($e['permissions']) && is_array($e['permissions'])
                ? array_values(array_map('strval', $e['permissions']))
                : [];
            $out[] = ['id' => $id, 'permissions' => $perms];
        }
        return $out;
    }

    private function extractToken(ServerRequestInterface $request): ?string
    {
        $auth = $request->getHeaderLine('Authorization');
        if ($auth !== '' && preg_match('/^Bearer\s+(.+)$/i', $auth, $m) === 1) {
            return $m[1];
        }
        $cookie = $request->getCookieParams()[$this->cookies->name()] ?? null;
        return is_string($cookie) && $cookie !== '' ? $cookie : null;
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
