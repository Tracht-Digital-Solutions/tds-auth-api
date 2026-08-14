<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Passkey;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\ChallengeStore;
use Tds\AuthApi\Service\PasskeyRepository;
use Tds\AuthApi\Service\WebAuthnFactory;

/**
 * POST /passkeys — finish registration.
 *
 * Body carries the browser's `PublicKeyCredential` as base64url:
 * `{clientDataJSON, attestationObject, name?}`. The challenge comes from the
 * signed cookie the options call set, never from the body — a client-chosen
 * challenge would let a replayed attestation register.
 */
final class RegisterAction
{
    public function __construct(
        private readonly PasskeyRepository $passkeys,
        private readonly WebAuthnFactory $webAuthn,
        private readonly ChallengeStore $challenges,
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        $claims = (array) $request->getAttribute(JwtAuthMiddleware::ATTR_CLAIMS, []);
        $userId = isset($claims['uid']) ? (int) $claims['uid'] : 0;
        if ($userId <= 0) {
            return $this->json($response, 401, ['error' => 'Unknown user']);
        }

        $challenge = $this->challenges->read(
            $request->getCookieParams()[$this->challenges->cookieName()] ?? null,
        );
        if ($challenge === null) {
            return $this->json($response, 400, ['error' => 'Challenge expired. Bitte erneut versuchen.']);
        }

        $body = (array) $request->getParsedBody();
        $clientDataJSON = self::decode((string) ($body['clientDataJSON'] ?? ''));
        $attestationObject = self::decode((string) ($body['attestationObject'] ?? ''));
        if ($clientDataJSON === '' || $attestationObject === '') {
            return $this->json($response, 400, ['error' => 'Malformed credential']);
        }

        try {
            $data = $this->webAuthn->create()->processCreate(
                clientDataJSON: $clientDataJSON,
                attestationObject: $attestationObject,
                challenge: $challenge,
                requireUserVerification: false,
                requireUserPresent: true,
                // Attestation is `none`, so there is no root chain to match.
                failIfRootMismatch: false,
            );
        } catch (\Throwable $e) {
            // The library's messages are precise and non-sensitive (bad origin,
            // bad signature, wrong rpId) — exactly what makes a failed
            // registration diagnosable instead of "es geht nicht".
            return $this->json($response, 422, ['error' => $e->getMessage()])
                ->withHeader('Set-Cookie', $this->challenges->expire());
        }

        $credentialId = (string) $data->credentialId;
        if ($this->passkeys->findByCredentialId($credentialId) !== null) {
            return $this->json($response, 409, ['error' => 'Dieser Passkey ist bereits registriert.'])
                ->withHeader('Set-Cookie', $this->challenges->expire());
        }

        $name = trim((string) ($body['name'] ?? ''));
        $this->passkeys->store(
            userId: $userId,
            credentialId: $credentialId,
            publicKeyPem: (string) $data->credentialPublicKey,
            signCount: is_int($data->signatureCounter) ? $data->signatureCounter : 0,
            name: $name !== '' ? mb_substr($name, 0, 100) : null,
        );

        return $this->json($response, 201, ['ok' => true, 'credentialId' => $credentialId])
            ->withHeader('Set-Cookie', $this->challenges->expire());
    }

    /** base64url → raw bytes; '' on anything unparseable. */
    private static function decode(string $value): string
    {
        if ($value === '') {
            return '';
        }
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        return is_string($decoded) ? $decoded : '';
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload, JSON_THROW_ON_ERROR));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
