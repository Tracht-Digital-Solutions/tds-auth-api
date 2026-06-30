<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Service\RateLimiter;
use Tds\AuthApi\Service\SessionRepository;

/**
 * POST /login   (alias: POST /customer/login)
 *
 * Body: {"email": "...", "password": "..."}.
 *
 * Unified login for both panels. On success it issues a JWT carrying the
 * user's actual `admin` flag, `customer_id` and portal `permissions`, records
 * the jti, and sets the cross-subdomain cookie. The admin panel calls the same
 * endpoint and checks `isAdmin` in the response.
 *
 * Constant-time miss handling: on email-not-found we still run password_verify
 * against a dummy argon2id hash so an attacker can't probe valid emails via
 * response-time difference.
 */
final class LoginAction
{
    private readonly string $dummyHash;

    public function __construct(
        private readonly AppUserRepository $users,
        private readonly JwtService $jwt,
        private readonly SessionRepository $sessions,
        private readonly CookieFactory $cookies,
        private readonly RateLimiter $rateLimiter,
    ) {
        $hash = password_hash('not-a-real-password', PASSWORD_ARGON2ID);
        $this->dummyHash = $hash !== false ? $hash : '';
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        // Rate-limit BEFORE validating the payload.
        $bucket = 'login:' . $this->clientIp($request);
        $rl = $this->rateLimiter->check($bucket);
        if (!$rl['allowed']) {
            return $this->json($response, 429, [
                'error' => 'Too many login attempts. Please try again later.',
            ]);
        }

        $body = $request->getParsedBody();
        $email = is_array($body) ? strtolower(trim((string) ($body['email'] ?? ''))) : '';
        $password = is_array($body) ? (string) ($body['password'] ?? '') : '';

        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false || $password === '') {
            return $this->json($response, 400, ['error' => 'Email and password required']);
        }

        $user = $this->users->findByEmail($email);

        if ($user === null) {
            password_verify($password, $this->dummyHash);
            return $this->json($response, 401, ['error' => 'Invalid credentials']);
        }

        if (!password_verify($password, $user->passwordHash)) {
            return $this->json($response, 401, ['error' => 'Invalid credentials']);
        }

        // Status checked only after a correct password so a disabled account
        // can't be distinguished from a wrong password by a probing attacker.
        if (!$user->isActive()) {
            return $this->json($response, 403, ['error' => 'Account disabled']);
        }

        $issued = $this->jwt->issueForUser($user);
        $this->sessions->record($issued['jti'], $user->customerId, $user->isAdmin, $issued['expiresAt'], $user->id);

        $response = $this->json($response, 200, [
            'token' => $issued['token'],
            'expiresAt' => $issued['expiresAt'],
            'userId' => $user->id,
            'isAdmin' => $user->isAdmin,
            'customerId' => $user->customerId,
            'permissions' => $user->isAdmin ? [] : $user->permissions,
            'mustChangePassword' => $user->mustChangePassword,
        ]);
        return $response->withHeader('Set-Cookie', $this->cookies->set($issued['token'], $this->jwt->ttl()));
    }

    private function clientIp(ServerRequestInterface $request): string
    {
        $forwarded = $request->getHeaderLine('X-Forwarded-For');
        if ($forwarded !== '') {
            return trim(explode(',', $forwarded)[0]);
        }
        $real = $request->getHeaderLine('X-Real-IP');
        if ($real !== '') {
            return $real;
        }
        return $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown';
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
