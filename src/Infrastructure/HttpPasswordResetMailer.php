<?php
declare(strict_types=1);

namespace Tds\AuthApi\Infrastructure;

use Tds\AuthApi\Service\PasswordResetMailer;

/**
 * POSTs the reset mail to tds-core-frontend-api's
 * `/internal/mail/password-reset`, authenticated with the shared service
 * token. That service renders the mail and sends it with the SMTP settings
 * from the panel (Einstellungen → E-Mail). Transport: ServiceMailCall.
 */
final class HttpPasswordResetMailer implements PasswordResetMailer
{
    public function __construct(
        private readonly string $frontendApiUrl,
        private readonly string $serviceToken,
        private readonly float $timeoutSeconds = 5.0,
    ) {
    }

    public function send(string $email, ?string $name, string $link, string $lang, int $validMinutes): bool
    {
        return ServiceMailCall::post(
            $this->frontendApiUrl,
            $this->serviceToken,
            '/internal/mail/password-reset',
            ['email' => $email, 'name' => $name, 'link' => $link, 'lang' => $lang, 'validMinutes' => $validMinutes],
            $this->timeoutSeconds,
            'password reset',
        );
    }
}
