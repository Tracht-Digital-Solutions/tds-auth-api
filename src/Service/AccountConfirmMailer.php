<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

/**
 * Delivers the confirmation link of a self-registered account. Like the reset
 * mail, it goes out through tds-core-frontend-api, which owns SMTP.
 */
interface AccountConfirmMailer
{
    /** @return bool whether the mail was handed over */
    public function send(string $email, ?string $name, string $link, string $lang, int $validHours): bool;
}
