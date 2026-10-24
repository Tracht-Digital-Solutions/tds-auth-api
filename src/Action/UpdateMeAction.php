<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\AppUserRepository;

/**
 * PATCH /me
 *
 * Body: {"displayName"?: string|null}
 *
 * The self-service half of the profile page. Deliberately tiny: the ONLY
 * thing a user may change about their own record here is the short name the
 * panel calls them by.
 *
 * What is NOT accepted, and why:
 *  - `name` — it is the account name an admin maintains and it drives the
 *    public blog byline and every admin user list. Letting a user rewrite it
 *    is a different decision from letting them pick a nickname.
 *  - `email` — it is the login identity and is uniquely indexed. Changing it
 *    needs a confirmation flow (and re-verification), not a PATCH.
 *  - `isAdmin`, `isSupportAgent`, `isBlogAuthor`, `status`, `permissions`,
 *    `memberships` — privilege. There is no path from this endpoint to any
 *    of them.
 *
 * Unknown keys are ignored rather than rejected: this is a partial update
 * whose whitelist is one field, and a 422 on every stray key would break the
 * moment a client sends back a whole `/me` object.
 *
 * Nothing here is authorization-relevant, so no sessions are revoked.
 *
 * Gated by JwtAuthMiddleware (any valid session).
 */
final class UpdateMeAction
{
    /** Matches the `display_name` column. */
    private const MAX_DISPLAY_NAME = 100;

    public function __construct(private readonly AppUserRepository $users)
    {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        /** @var array<string,mixed> $claims */
        $claims = (array) $request->getAttribute(JwtAuthMiddleware::ATTR_CLAIMS, []);
        $uid = isset($claims['uid']) && is_int($claims['uid']) ? $claims['uid'] : 0;

        $user = $uid > 0 ? $this->users->findById($uid) : null;
        if ($user === null) {
            return $this->json($response, 401, ['error' => 'User not found']);
        }

        $body = $request->getParsedBody();
        if (!is_array($body)) {
            return $this->json($response, 400, ['error' => 'JSON body required']);
        }

        $fields = [];

        if (array_key_exists('displayName', $body)) {
            $raw = $body['displayName'];
            if ($raw !== null && !is_string($raw)) {
                return $this->json($response, 422, ['error' => 'displayName must be a string or null']);
            }
            $trimmed = trim((string) ($raw ?? ''));
            // Empty means "clear it" — the label falls back to `name`, then
            // to the email, so the panel can never end up with a blank header.
            $fields['display_name'] = $trimmed === ''
                ? null
                : mb_substr($trimmed, 0, self::MAX_DISPLAY_NAME);
        }

        if ($fields !== []) {
            $this->users->update($uid, $fields);
        }

        $fresh = $this->users->findById($uid);
        return $this->json($response, 200, ['user' => ($fresh ?? $user)->toPublicArray()]);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
