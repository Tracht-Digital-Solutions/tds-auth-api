<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Customer;

use PDO;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Service\RateLimiter;
use Tds\AuthApi\Service\SessionRepository;

/**
 * POST /customer/login
 *
 * Body: {"email": "...", "password": "..."}.
 *
 * On success: issues a customer JWT (admin=false, customer_id=N),
 * records the jti in `session`, and sets the cross-subdomain cookie
 * so subsequent calls to tds-customer-api auto-attach it.
 *
 * Constant-time miss handling: on email-not-found we still run
 * password_verify against a dummy argon2id hash. Without this, an
 * attacker can probe valid emails via response-time difference.
 */
final class LoginAction
{
    private readonly string $dummyHash;

    public function __construct(
        private readonly PDO $pdo,
        private readonly JwtService $jwt,
        private readonly SessionRepository $sessions,
        private readonly CookieFactory $cookies,
        private readonly RateLimiter $rateLimiter,
    ) {
        // Hash a fixed throwaway value once at construction. The cost
        // is one argon2id hash per FPM worker startup, much cheaper
        // than embedding a literal hash that might not parse across
        // PHP/libsodium versions.
        $hash = password_hash('not-a-real-password', PASSWORD_ARGON2ID);
        $this->dummyHash = $hash !== false ? $hash : '';
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        // Rate-limit BEFORE validating the payload — payload validation
        // is cheap and an attacker probing with garbage bodies should
        // still pay the limiter cost.
        $bucket = 'customer:' . $this->clientIp($request);
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

        $row = $this->lookupByEmail($email);

        if (!is_array($row)) {
            password_verify($password, $this->dummyHash);
            return $this->json($response, 401, ['error' => 'Invalid credentials']);
        }

        if (!password_verify($password, (string) $row['password_hash'])) {
            return $this->json($response, 401, ['error' => 'Invalid credentials']);
        }

        $customerId = (int) $row['customer_id'];
        $issued = $this->jwt->issueCustomer($customerId);
        $this->sessions->record($issued['jti'], $customerId, false, $issued['expiresAt']);

        $response = $this->json($response, 200, [
            'token' => $issued['token'],
            'expiresAt' => $issued['expiresAt'],
            'customerId' => $customerId,
        ]);
        return $response->withHeader('Set-Cookie', $this->cookies->set($issued['token'], $this->jwt->ttl()));
    }

    /** @return array{customer_id:int, password_hash:string}|false */
    private function lookupByEmail(string $email): array|false
    {
        $stmt = $this->pdo->prepare(
            'SELECT customer_id, password_hash FROM customer_credential WHERE email = :email LIMIT 1'
        );
        $stmt->execute(['email' => $email]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : false;
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
