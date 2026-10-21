<?php
declare(strict_types=1);

namespace Tds\AuthApi\Infrastructure;

use Tds\AuthApi\Service\PasswordResetMailer;

/**
 * POSTs the reset mail to tds-core-frontend-api's
 * `/internal/mail/password-reset`, authenticated with the shared service
 * token. That service renders the mail and sends it with the SMTP settings
 * from the panel (Einstellungen → E-Mail).
 *
 * Plain PHP streams, no HTTP client dependency: this service shares one PHP
 * process with the others in the gateway's in-process mode, and every shared
 * package is a version that can collide (tds-gateway-api#8).
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
        if ($this->frontendApiUrl === '' || $this->serviceToken === '') {
            error_log('[tds-auth-api] password reset: FRONTEND_API_URL or the service token is not set, no mail sent');
            return false;
        }

        $body = json_encode([
            'email' => $email,
            'name' => $name,
            'link' => $link,
            'lang' => $lang,
            'validMinutes' => $validMinutes,
        ]);
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\n"
                    . "Authorization: Bearer {$this->serviceToken}\r\n",
                'content' => $body,
                'timeout' => $this->timeoutSeconds,
                'ignore_errors' => true,
            ],
        ]);

        $url = rtrim($this->frontendApiUrl, '/') . '/internal/mail/password-reset';
        $result = @file_get_contents($url, false, $context);
        $status = self::statusOf($http_response_header ?? []);
        if ($result === false || $status < 200 || $status >= 300) {
            error_log("[tds-auth-api] password reset: mail call to {$url} failed (HTTP {$status})");
            return false;
        }
        return true;
    }

    /** @param list<string> $headers */
    private static function statusOf(array $headers): int
    {
        // The last status line wins: a redirect leaves several.
        $status = 0;
        foreach ($headers as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
                $status = (int) $m[1];
            }
        }
        return $status;
    }
}
