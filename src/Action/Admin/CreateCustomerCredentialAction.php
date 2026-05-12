<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin;

use PDO;
use PDOException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;

/**
 * POST /admin/customer-credentials
 *
 * Called server-to-server by tds-customer-api during customer
 * onboarding. The caller has already inserted the `customer` row;
 * this action hashes the temp password (argon2id) and stores the
 * credential. The customer can then log in via POST /customer/login.
 *
 * Body: {"customer_id": int, "email": string, "password": string}.
 * 201 on success, 409 if the email is already credentialed, 422 on
 * validation failure. AdminAuthMiddleware gates the route.
 */
final class CreateCustomerCredentialAction
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $body = $request->getParsedBody();
        if (!is_array($body)) {
            return $this->json($response, 400, ['error' => 'Invalid JSON body']);
        }

        $customerId = (int) ($body['customer_id'] ?? 0);
        $email = strtolower(trim((string) ($body['email'] ?? '')));
        $password = (string) ($body['password'] ?? '');

        if ($customerId <= 0) {
            return $this->json($response, 422, ['error' => 'customer_id must be a positive integer']);
        }
        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            return $this->json($response, 422, ['error' => 'Valid email required']);
        }
        // Temp passwords come from the onboarding caller; keep the
        // minimum loose so a 16-char URL-safe value passes.
        if (strlen($password) < 12) {
            return $this->json($response, 422, ['error' => 'Password must be at least 12 characters']);
        }

        $hash = password_hash($password, PASSWORD_ARGON2ID);
        if ($hash === false) {
            return $this->json($response, 500, ['error' => 'Hashing failed']);
        }

        try {
            $stmt = $this->pdo->prepare(
                'INSERT INTO customer_credential (customer_id, email, password_hash, created_at, updated_at) '
                . 'VALUES (:cid, :email, :hash, NOW(), NOW())'
            );
            $stmt->execute([
                'cid' => $customerId,
                'email' => $email,
                'hash' => $hash,
            ]);
        } catch (PDOException $e) {
            // 23000 = integrity constraint violation (unique email collides).
            if ($e->getCode() === '23000') {
                return $this->json($response, 409, ['error' => 'Email already has a credential']);
            }
            throw $e;
        }

        return $this->json($response, 201, ['ok' => true]);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
