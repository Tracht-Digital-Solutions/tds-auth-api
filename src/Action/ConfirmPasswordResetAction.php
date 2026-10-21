<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\ClientIp;
use Tds\AuthApi\Service\PasswordResetRepository;
use Tds\AuthApi\Service\RateLimiter;
use Tds\AuthApi\Service\RememberTokenService;
use Tds\AuthApi\Service\SessionRepository;

/**
 * POST /password-reset/confirm
 *
 * Body: {"token": "...", "new": "..."}. Answers 204; the user then signs in
 * with the new password. No session is issued here — a mailed link is not a
 * second factor, and a login afterwards keeps every login rule in one place.
 *
 * The password rules are checked BEFORE the token is consumed, so a too-short
 * password does not burn the link. A successful reset revokes every session
 * and every "angemeldet bleiben" token of the user: otherwise a device the
 * user no longer trusts keeps its access for 30 days and the reset is theatre.
 */
final class ConfirmPasswordResetAction
{
    public function __construct(
        private readonly AppUserRepository $users,
        private readonly PasswordResetRepository $resets,
        private readonly SessionRepository $sessions,
        private readonly RememberTokenService $remember,
        private readonly RateLimiter $rateLimiter,
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        if (!$this->rateLimiter->check('reset-confirm:' . ClientIp::from($request))['allowed']) {
            return $this->json($response, 429, ['error' => 'Too many requests. Please try again later.']);
        }

        $body = $request->getParsedBody();
        $token = is_array($body) ? trim((string) ($body['token'] ?? '')) : '';
        $new = is_array($body) ? (string) ($body['new'] ?? '') : '';

        if ($token === '' || $new === '') {
            return $this->json($response, 400, ['error' => 'Token and new password required']);
        }
        if (strlen($new) < 12) {
            return $this->json($response, 422, ['error' => 'New password must be at least 12 characters']);
        }

        $userId = $this->resets->consume(hash('sha256', $token));
        $user = $userId !== null ? $this->users->findById($userId) : null;
        if ($user === null || !$user->isActive()) {
            return $this->json($response, 400, ['error' => 'Invalid or expired link']);
        }

        $hash = password_hash($new, PASSWORD_ARGON2ID);
        if ($hash === false) {
            return $this->json($response, 500, ['error' => 'Hashing failed']);
        }

        $this->users->updatePassword($user->id, $hash);
        // A self-chosen password replaces an admin-issued temporary one.
        if ($user->mustChangePassword) {
            $this->users->update($user->id, ['must_change_password' => false]);
        }
        $this->resets->deleteForUser($user->id);
        $this->sessions->revokeAllForUser($user->id);
        $this->remember->forgetAllForUser($user->id);

        return $response->withStatus(204);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
