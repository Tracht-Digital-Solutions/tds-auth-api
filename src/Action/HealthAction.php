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
        // Two-stage probe: connectivity first, then schema presence. A bare
        // `SELECT 1` succeeds against an empty (un-migrated) database, so it
        // reports `ok` while /login 500s on the missing tables — that masked a
        // production outage (tds-auth-api#13). Probing a real table
        // distinguishes "reachable but never migrated" from "reachable + ready".
        try {
            $pdo = ($this->pdo)();
            $pdo->query('SELECT 1');
        } catch (\Throwable) {
            return 'down';
        }

        try {
            $pdo->query('SELECT 1 FROM `session` LIMIT 1');
            return 'ok';
        } catch (\Throwable $e) {
            return self::isMissingTable($e) ? 'no-schema' : 'down';
        }
    }

    /**
     * MySQL/MariaDB SQLSTATE 42S02 = "base table or view not found", i.e. the
     * DB is reachable but the migrations were never applied.
     */
    private static function isMissingTable(\Throwable $e): bool
    {
        return ($e instanceof \PDOException && $e->getCode() === '42S02')
            || str_contains($e->getMessage(), '42S02');
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
