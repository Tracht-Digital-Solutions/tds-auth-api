<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\AvatarRepository;

/**
 * DELETE /me/avatar
 *
 * Drops the caller's picture and clears `app_user.avatar_url`, so the panel
 * falls back to the initials avatar. Idempotent: deleting a picture that is
 * not there is a 200, not a 404 — the caller's intent ("I should have no
 * avatar") is satisfied either way.
 *
 * Gated by JwtAuthMiddleware (any valid session); the target comes from the
 * token, never the request.
 */
final class DeleteAvatarAction
{
    public function __construct(
        private readonly AppUserRepository $users,
        private readonly AvatarRepository $avatars,
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

        $this->avatars->delete($uid);
        $this->users->update($uid, ['avatar_url' => null]);

        return $this->json($response, 200, ['ok' => true]);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
