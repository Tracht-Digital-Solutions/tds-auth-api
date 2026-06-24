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
    /**
     * Both deps are lazy providers, resolved inside the checks' try/catch so a
     * DB outage / corrupt-or-missing key reports `down`/`missing` with HTTP 200
     * instead of 5xx'ing during construction (the documented "never 5xx").
     *
     * @param \Closure(): PDO $pdo
     * @param \Closure(): JwtService $jwt
     */
    public function __construct(
        private readonly \Closure $pdo,
        private readonly \Closure $jwt,
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
            ($this->pdo)()->query('SELECT 1');
            return 'ok';
        } catch (\Throwable) {
            return 'down';
        }
    }

    private function checkKeys(): string
    {
        try {
            return ($this->jwt)()->keyHealth() ? 'loaded' : 'missing';
        } catch (\Throwable) {
            return 'missing';
        }
    }
}
