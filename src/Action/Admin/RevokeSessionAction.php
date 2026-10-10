<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\SessionRepository;

/**
 * DELETE /admin/sessions/{jti}
 *
 * Forcibly revokes a session by jti. Idempotent — calling on an
 * already-revoked or unknown jti is a 204 either way (the
 * `SessionRepository::revoke()` `UPDATE ... WHERE revoked_at IS NULL`
 * clause is a no-op when the row is missing or already revoked).
 *
 * Gated by AdminAuthMiddleware.
 */
final class RevokeSessionAction
{
    public function __construct(private readonly SessionRepository $sessions)
    {
    }

    /** @param array<string,string> $args */
    public function __invoke(ServerRequestInterface $request, Response $response, array $args): ResponseInterface
    {
        $jti = $args['jti'] ?? '';
        if ($jti === '') {
            $response->getBody()->write(json_encode(['error' => 'jti required']));
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
        }

        $this->sessions->revoke($jti);

        return $response->withStatus(204);
    }
}
