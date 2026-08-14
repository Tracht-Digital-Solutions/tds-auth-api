<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Passkey;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\ChallengeStore;
use Tds\AuthApi\Service\WebAuthnFactory;

/**
 * POST /passkeys/login/options — request options for a passkey sign-in.
 *
 * **No email, and no `allowCredentials`.** The credential list is left empty on
 * purpose: the authenticator offers its discoverable credentials for this
 * relying party and the user picks one, so the browser never has to be told
 * which account is being signed into. Two things follow, both wanted —
 *
 *  - there is no account-enumeration surface here at all (an
 *    `allowCredentials` list keyed by a submitted email answers "does this
 *    address have a passkey?" for anyone who asks), and
 *  - sign-in needs no typing, which is the entire point of a passkey.
 *
 * Unauthenticated by definition. The response is not a credential and reveals
 * nothing: a random challenge and the relying-party id.
 */
final class LoginOptionsAction
{
    public function __construct(
        private readonly WebAuthnFactory $webAuthn,
        private readonly ChallengeStore $challenges,
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $lib = $this->webAuthn->create();
        $args = $lib->getGetArgs(
            credentialIds: [],
            timeout: 60,
        );

        $response->getBody()->write(json_encode($args, JSON_THROW_ON_ERROR));
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Set-Cookie', $this->challenges->issue($lib->getChallenge()->getBinaryString()));
    }
}
