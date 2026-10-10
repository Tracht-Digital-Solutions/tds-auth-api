<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Passkey;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\ChallengeStore;
use Tds\AuthApi\Service\PasskeyRepository;
use Tds\AuthApi\Service\WebAuthnFactory;

/**
 * POST /passkeys/options — creation options for registering a new passkey.
 * Requires a valid session: you add a passkey to the account you are signed
 * into.
 *
 * **Resident (discoverable) credentials are required.** Sign-in here carries no
 * email — the authenticator names the account — so a non-discoverable credential
 * would register successfully and then be unusable for login, which is a
 * particularly unpleasant failure to debug.
 *
 * Already-registered credential ids are excluded so a second registration on the
 * same device updates nothing and reports a clean browser-level error instead of
 * creating a duplicate row.
 */
final class RegisterOptionsAction
{
    public function __construct(
        private readonly AppUserRepository $users,
        private readonly PasskeyRepository $passkeys,
        private readonly WebAuthnFactory $webAuthn,
        private readonly ChallengeStore $challenges,
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $claims = (array) $request->getAttribute(JwtAuthMiddleware::ATTR_CLAIMS, []);
        $userId = isset($claims['uid']) ? (int) $claims['uid'] : 0;
        $user = $userId > 0 ? $this->users->findById($userId) : null;
        if ($user === null) {
            $response->getBody()->write(json_encode(['error' => 'Unknown user']));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }

        $lib = $this->webAuthn->create();
        $args = $lib->getCreateArgs(
            userId: (string) $user->id,
            userName: $user->email,
            userDisplayName: $user->name !== null && $user->name !== '' ? $user->name : $user->email,
            timeout: 60,
            requireResidentKey: true,
            requireUserVerification: 'preferred',
            crossPlatformAttachment: null,
            excludeCredentialIds: $this->passkeys->credentialIdsForUser($user->id),
        );

        $response->getBody()->write(json_encode($args, JSON_THROW_ON_ERROR));
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Set-Cookie', $this->challenges->issue($lib->getChallenge()->getBinaryString()));
    }
}
