<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\SessionRepository;

/**
 * DELETE /me/sessions/{jti}
 *
 * Ends one of the caller's own sessions — "auf diesem anderen Gerät abmelden".
 *
 * **Ownership is proved before revoking.** `SessionRepository::revoke()`
 * revokes whatever jti it is handed, with no notion of who owns it, so this
 * reads the owner first. A session belonging to someone else answers **404,
 * not 403**: a 403 would confirm that the jti exists, turning this route into
 * an existence oracle for other people's sessions. A jti that is unknown,
 * already revoked or expired answers 404 for the same reason.
 *
 * Revoking the CURRENT session is allowed — that is just logging out from the
 * session list, and the panel's 401 backstop takes it from there.
 *
 * Gated by JwtAuthMiddleware (any valid session).
 */
final class RevokeMySessionAction
{
    public function __construct(private readonly SessionRepository $sessions)
    {
    }

    public function __invoke(
        ServerRequestInterface $request,
        Response $response,
        array $args = [],
    ): ResponseInterface {
        /** @var array<string,mixed> $claims */
        $claims = (array) $request->getAttribute(JwtAuthMiddleware::ATTR_CLAIMS, []);
        $uid = isset($claims['uid']) && is_int($claims['uid']) ? $claims['uid'] : 0;

        if ($uid <= 0) {
            return $this->json($response, 401, ['error' => 'Unauthorized']);
        }

        $jti = trim((string) ($args['jti'] ?? ''));
        if ($jti === '' || $this->sessions->ownerOf($jti) !== $uid) {
            return $this->json($response, 404, ['error' => 'Session not found']);
        }

        $this->sessions->revoke($jti);

        return $this->json($response, 200, ['ok' => true]);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
