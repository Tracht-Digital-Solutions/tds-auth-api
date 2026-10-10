<?php

declare(strict_types=1);

namespace Tds\AuthApi\Service;

use Psr\Http\Message\ServerRequestInterface;

/**
 * The client address to rate-limit on.
 *
 * The login and passkey actions used the FIRST `X-Forwarded-For` entry, which
 * is whatever the client sent: every request could claim a fresh address, so
 * the limiter never limited anything, and a long enough value overflowed the
 * 100-character bucket column into a 500. The gateway APPENDS the address it
 * saw (`DispatchAction::forwardedFor`), so the trustworthy entry is the LAST
 * one; without the header, the socket address is the answer.
 */
final class ClientIp
{
    public static function from(ServerRequestInterface $request): string
    {
        $forwarded = $request->getHeaderLine('X-Forwarded-For');
        if ($forwarded !== '') {
            $parts = array_map('trim', explode(',', $forwarded));
            $candidate = (string) end($parts);
        } else {
            $candidate = (string) ($request->getServerParams()['REMOTE_ADDR'] ?? '');
        }

        return filter_var($candidate, FILTER_VALIDATE_IP) !== false ? $candidate : 'unknown';
    }
}
