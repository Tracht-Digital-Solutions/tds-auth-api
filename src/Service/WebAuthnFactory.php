<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

use lbuchs\WebAuthn\WebAuthn;

/**
 * Builds the WebAuthn verifier with this deployment's relying-party identity.
 *
 * **The RP ID is the registrable domain, not the login host.** `tracht-digital.de`
 * (not `auth.tracht-digital.de`) is what makes one passkey usable on every
 * first-party frontend: an origin satisfies an RP ID when the RP ID is a
 * registrable-domain suffix of it, so `auth.`, `management.`, `app.` and
 * `tools.` all match while nothing outside the domain does. Registering under
 * the login host instead would silently produce passkeys that only work there.
 *
 * Attestation is deliberately **`none`**: TDS does not restrict which
 * authenticators may be used, and asking for attestation would collect device
 * identifiers with no purpose here beyond a privacy prompt in some browsers.
 */
final class WebAuthnFactory
{
    public function __construct(
        private readonly string $rpName,
        private readonly string $rpId,
    ) {
    }

    public function rpId(): string
    {
        return $this->rpId;
    }

    public function create(): WebAuthn
    {
        // `useBase64UrlEncoding: true` makes every ByteBuffer serialise as
        // base64url, which is exactly what `PublicKeyCredential` expects on the
        // wire — so the browser-side glue stays a plain base64url decode with no
        // per-field special cases.
        return new WebAuthn($this->rpName, $this->rpId, ['none'], true);
    }
}
