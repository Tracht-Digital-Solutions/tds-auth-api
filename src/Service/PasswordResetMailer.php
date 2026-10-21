<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

/**
 * Delivers the reset link. This service has no SMTP of its own: the mail goes
 * out through tds-core-frontend-api, which owns the panel's mail settings.
 */
interface PasswordResetMailer
{
    /** @return bool whether the mail was handed over */
    public function send(string $email, ?string $name, string $link, string $lang, int $validMinutes): bool;
}
