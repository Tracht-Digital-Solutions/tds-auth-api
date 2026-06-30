<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Domain\Permissions;
use Tds\AuthApi\Service\AppUserRepository;

/**
 * POST /admin/customer-credentials
 *
 * Called server-to-server by tds-customer-api during customer onboarding. The
 * caller has already inserted the `customer` (company) row; this action creates
 * the matching login as an app_user (is_admin=0, tied to customer_id, full
 * portal access by default). The account can then log in via POST /login.
 *
 * Body: {"customer_id": int, "email": string, "password": string,
 *        "name"?: string, "permissions"?: string[]}.
 * 201 on success, 409 if the email already has a login, 422 on validation
 * failure. Gated by the service-token AdminAuthMiddleware (SERVICE_TOKEN).
 */
final class CreateCustomerCredentialAction
{
    public function __construct(private readonly AppUserRepository $users)
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
        $name = isset($body['name']) && trim((string) $body['name']) !== '' ? trim((string) $body['name']) : null;

        if ($customerId <= 0) {
            return $this->json($response, 422, ['error' => 'customer_id must be a positive integer']);
        }
        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            return $this->json($response, 422, ['error' => 'Valid email required']);
        }
        // Temp passwords come from the onboarding caller; keep the minimum
        // loose so a 16-char URL-safe value passes.
        if (strlen($password) < 12) {
            return $this->json($response, 422, ['error' => 'Password must be at least 12 characters']);
        }

        // Default a freshly onboarded customer to full portal access; the
        // caller may narrow it via an explicit permissions list.
        $permissions = array_key_exists('permissions', $body)
            ? Permissions::sanitize($body['permissions'])
            : Permissions::ALL;

        if ($this->users->emailExists($email)) {
            return $this->json($response, 409, ['error' => 'Email already has a credential']);
        }

        $hash = password_hash($password, PASSWORD_ARGON2ID);
        if ($hash === false) {
            return $this->json($response, 500, ['error' => 'Hashing failed']);
        }

        $this->users->create($email, $hash, $name, false, $customerId, $permissions, 'active');

        return $this->json($response, 201, ['ok' => true]);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
