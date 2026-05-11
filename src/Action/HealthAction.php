<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action;

use PDO;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\JwtService;

/**
 * GET /healthz
 *
 * Liveness + dependency probe. Never 5xx's so monitors can rely on
 * the 200 + JSON contract rather than status codes.
 *
 * The `keys` check signs a throwaway probe payload to confirm the
 * loaded private key is actually usable — catches "key file present
 * but corrupted" before a real /admin/login does.
 */
final class HealthAction
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly JwtService $jwt,
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $payload = [
            'status' => 'ok',
            'db' => $this->checkDb(),
            'keys' => $this->checkKeys(),
            'commit' => trim((string) (getenv('GIT_COMMIT') ?: 'unknown')),
        ];
        $response->getBody()->write(json_encode($payload));
        return $response
            ->withStatus(200)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Cache-Control', 'no-store');
    }

    private function checkDb(): string
    {
        try {
            $this->pdo->query('SELECT 1');
            return 'ok';
        } catch (\Throwable) {
            return 'down';
        }
    }

    private function checkKeys(): string
    {
        return $this->jwt->keyHealth() ? 'loaded' : 'missing';
    }
}
