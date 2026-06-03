<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Customer;

use PDO;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\CustomerAuthMiddleware;
use Tds\AuthApi\Service\CookieFactory;
use Tds\AuthApi\Service\JwtService;
use Tds\AuthApi\Service\SessionRepository;

/**
 * PUT /customer/password
 *
 * Body: {"old": "...", "new": "..."}.
 *
 * Gated by CustomerAuthMiddleware, which authenticates the customer
 * JWT and exposes the customer id and jti as request attributes.
 * Verifies the old password against the stored argon2id hash,
 * rehashes the new password, revokes the current jti and issues a
 * fresh JWT — so any other live tab/device using the old token is
 * forced through login on its next refresh.
 */
final class ChangePasswordAction
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly JwtService $jwt,
        private readonly SessionRepository $sessions,
        private readonly CookieFactory $cookies,
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $customerId = (int) $request->getAttribute(CustomerAuthMiddleware::ATTR_CUSTOMER_ID);
        $jti = (string) $request->getAttribute(CustomerAuthMiddleware::ATTR_JTI);

        $body = $request->getParsedBody();
        $old = is_array($body) ? (string) ($body['old'] ?? '') : '';
        $new = is_array($body) ? (string) ($body['new'] ?? '') : '';

        if ($old === '' || $new === '') {
            return $this->json($response, 400, ['error' => 'Old and new password required']);
        }
        if (strlen($new) < 12) {
            return $this->json($response, 422, ['error' => 'New password must be at least 12 characters']);
        }
        if (hash_equals($old, $new)) {
            return $this->json($response, 422, ['error' => 'New password must differ from old']);
        }

        $row = $this->lookupByCustomerId($customerId);
        if (!is_array($row)) {
            // Token said customer N exists but the credential row is gone.
            // Treat as logout — revoke and force re-login.
            $this->sessions->revoke($jti);
            return $this->json($response, 401, ['error' => 'Credential not found'])
                ->withHeader('Set-Cookie', $this->cookies->expire());
        }

        if (!password_verify($old, (string) $row['password_hash'])) {
            return $this->json($response, 401, ['error' => 'Old password incorrect']);
        }

        $hash = password_hash($new, PASSWORD_ARGON2ID);
        if ($hash === false) {
            return $this->json($response, 500, ['error' => 'Hashing failed']);
        }

        $update = $this->pdo->prepare(
            'UPDATE customer_credential SET password_hash = :hash, updated_at = NOW() WHERE customer_id = :cid'
        );
        $update->execute(['hash' => $hash, 'cid' => $customerId]);

        // Revoke the jti carrying the old credential, then issue a
        // fresh session so the caller stays logged in. Any *other*
        // device on the old jti will fail its next refresh.
        $this->sessions->revoke($jti);
        $issued = $this->jwt->issueCustomer($customerId);
        $this->sessions->record($issued['jti'], $customerId, false, $issued['expiresAt']);

        return $this->json($response, 200, [
            'token' => $issued['token'],
            'expiresAt' => $issued['expiresAt'],
            'customerId' => $customerId,
        ])->withHeader('Set-Cookie', $this->cookies->set($issued['token'], $this->jwt->ttl()));
    }

    /** @return array{password_hash:string}|false */
    private function lookupByCustomerId(int $customerId): array|false
    {
        $stmt = $this->pdo->prepare(
            'SELECT password_hash FROM customer_credential WHERE customer_id = :cid LIMIT 1'
        );
        $stmt->execute(['cid' => $customerId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return is_array($row) ? $row : false;
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
