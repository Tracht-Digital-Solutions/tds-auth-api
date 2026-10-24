<?php
declare(strict_types=1);

namespace Tds\AuthApi\Infrastructure;

use Tds\AuthApi\Service\AccountConfirmMailer;

/**
 * POSTs the confirmation mail to tds-core-frontend-api's
 * `/internal/mail/account-confirm` with the shared service token — the same
 * transport as HttpPasswordResetMailer.
 */
final class HttpAccountConfirmMailer implements AccountConfirmMailer
{
    public function __construct(
        private readonly string $frontendApiUrl,
        private readonly string $serviceToken,
        private readonly float $timeoutSeconds = 5.0,
    ) {
    }

    public function send(string $email, ?string $name, string $link, string $lang, int $validHours): bool
    {
        return ServiceMailCall::post(
            $this->frontendApiUrl,
            $this->serviceToken,
            '/internal/mail/account-confirm',
            ['email' => $email, 'name' => $name, 'link' => $link, 'lang' => $lang, 'validHours' => $validHours],
            $this->timeoutSeconds,
            'account confirmation',
        );
    }
}
