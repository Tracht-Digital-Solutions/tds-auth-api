<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\AppUserRepository;

/**
 * GET /me
 *
 * Returns the current authenticated principal. Both panels call this to drive
 * UI gating (the JWT lives in an httpOnly cookie and isn't readable from JS).
 * Re-reads the user row so name / permissions / admin flag reflect the latest
 * state even before the token refreshes.
 *
 * Gated by JwtAuthMiddleware (any valid session).
 */
final class MeAction
{
    public function __construct(private readonly AppUserRepository $users)
    {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        /** @var array<string,mixed> $claims */
        $claims = (array) $request->getAttribute(JwtAuthMiddleware::ATTR_CLAIMS, []);
        $uid = isset($claims['uid']) && is_int($claims['uid']) ? $claims['uid'] : 0;

        $user = $uid > 0 ? $this->users->findById($uid) : null;
        if ($user === null) {
            return $this->json($response, 401, ['error' => 'User not found']);
        }

        return $this->json($response, 200, [
            'userId' => $user->id,
            'email' => $user->email,
            'name' => $user->name,
            'isAdmin' => $user->isAdmin,
            'isSupportAgent' => $user->isAdmin && $user->isSupportAgent,
            'isBlogAuthor' => $user->isBlogAuthor,
            'avatarUrl' => $user->avatarUrl,
            'companies' => $user->isAdmin
                ? []
                : array_map(static fn ($m) => $m->toArray(), $user->memberships),
            'customerId' => $user->customerId,
            'permissions' => $user->isAdmin ? [] : $user->permissions,
            'mustChangePassword' => $user->mustChangePassword,
            // Session expiry (Unix seconds) straight from the verified token's
            // `exp` claim — lets the panels' inline gate bounce an expired
            // session to /login before the panel paints (no stale-hint flash).
            'expiresAt' => isset($claims['exp']) && is_int($claims['exp']) ? $claims['exp'] : null,
        ]);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
