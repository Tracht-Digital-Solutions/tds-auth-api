<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\AvatarRepository;
use Tds\AuthApi\Service\PermissionResolver;

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
    public function __construct(
        private readonly AppUserRepository $users,
        private readonly AvatarRepository $avatars,
        private readonly PermissionResolver $permissions,
    ) {
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
            'displayName' => $user->displayName,
            // What a UI should actually print — displayName, else name, else
            // the email. Resolved here so the profile menu, the user list and
            // any future consumer can't each invent a different fallback and
            // end up showing a blank header for an account with no name.
            'label' => $user->label(),
            'isAdmin' => $user->isAdmin,
            'isSupportAgent' => $user->isAdmin && $user->isSupportAgent,
            'isBlogAuthor' => $user->isBlogAuthor,
            'avatarUrl' => $user->avatarUrl,
            // Whether an uploaded picture actually exists, which is NOT the
            // same as `avatarUrl` being set: the column has held a URL into
            // the archived tds-content-api's /uploads since 20260707000001,
            // and those files are gone. The profile page uses this to decide
            // whether to offer "Entfernen".
            'hasAvatar' => $this->avatars->meta($user->id) !== null,
            // RESOLVED, not the raw rows: the panel decides from this whether
            // to offer "Meine Firma" and which rights to show as held, and the
            // stored row knows neither what the groups add nor whether the
            // company's delegation is switched on. Emitting it raw is how the
            // nav came to advertise a page the server refuses.
            'companies' => $user->isAdmin
                ? []
                : array_map(
                    fn ($m) => $this->permissions->effective($user->id, $m)->toArray(),
                    $user->memberships,
                ),
            'companyId' => $user->companyId,
            // Deprecated alias, emitted for one release so a client built
            // against the old name keeps working. Dropped in the follow-up.
            'customerId' => $user->companyId,
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
