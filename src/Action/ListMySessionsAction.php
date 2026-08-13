<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\SessionRepository;

/**
 * GET /me/sessions
 *
 * The caller's own still-valid sessions, for the profile page's Sicherheit
 * tab. The equivalent admin route (`GET /admin/sessions`) lists EVERY user's
 * sessions and is gated on the admin claim; this one is scoped in SQL, so a
 * self-service caller is never handed rows it then has to filter.
 *
 * `current: true` marks the session making the request, which is the one piece
 * of information that makes the list actionable — otherwise "Abmelden" on an
 * unlabelled row is a coin flip.
 *
 * Gated by JwtAuthMiddleware (any valid session).
 */
final class ListMySessionsAction
{
    public function __construct(private readonly SessionRepository $sessions)
    {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        /** @var array<string,mixed> $claims */
        $claims = (array) $request->getAttribute(JwtAuthMiddleware::ATTR_CLAIMS, []);
        $uid = isset($claims['uid']) && is_int($claims['uid']) ? $claims['uid'] : 0;
        $currentJti = (string) ($claims['jti'] ?? '');

        if ($uid <= 0) {
            return $this->json($response, 401, ['error' => 'Unauthorized']);
        }

        $sessions = array_map(static fn (array $s): array => [
            'jti' => $s['jti'],
            'createdAt' => $s['created_at'],
            'expiresAt' => $s['expires_at'],
            'admin' => $s['admin'],
            'current' => $s['jti'] === $currentJti,
        ], $this->sessions->listActiveForUser($uid));

        return $this->json($response, 200, ['sessions' => $sessions]);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
