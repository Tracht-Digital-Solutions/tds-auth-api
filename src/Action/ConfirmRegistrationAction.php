<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\AccountConfirmRepository;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\ClientIp;
use Tds\AuthApi\Service\RateLimiter;

/**
 * POST /register/confirm
 *
 * Body: {"token": "..."}. Answers 204; the user then signs in with the
 * password chosen at registration. No session is issued here, as with the
 * reset: a login afterwards keeps every login rule in one place.
 *
 * Only a still pending account is activated. A link for an account that is
 * already active (or was disabled by an admin meanwhile) changes nothing — a
 * stale mail must never overwrite a password or revive a disabled account.
 */
final class ConfirmRegistrationAction
{
    public function __construct(
        private readonly AppUserRepository $users,
        private readonly AccountConfirmRepository $confirms,
        private readonly RateLimiter $rateLimiter,
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        if (!$this->rateLimiter->check('register-confirm:' . ClientIp::from($request))['allowed']) {
            return $this->json($response, 429, ['error' => 'Too many requests. Please try again later.']);
        }

        $body = $request->getParsedBody();
        $token = is_array($body) ? trim((string) ($body['token'] ?? '')) : '';
        if ($token === '') {
            return $this->json($response, 400, ['error' => 'Token required']);
        }

        $grant = $this->confirms->consume(hash('sha256', $token));
        $user = $grant !== null ? $this->users->findById($grant['userId']) : null;
        if ($grant === null || $user === null || $user->status !== 'pending') {
            return $this->json($response, 400, ['error' => 'Invalid or expired link']);
        }

        $this->users->updatePassword($user->id, $grant['passwordHash']);
        $this->users->update($user->id, ['status' => 'active', 'name' => $grant['name'] ?? $user->name]);
        $this->confirms->deleteForUser($user->id);

        return $response->withStatus(204);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
