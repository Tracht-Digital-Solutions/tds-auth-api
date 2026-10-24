<?php
declare(strict_types=1);

namespace Tds\AuthApi\Infrastructure;

/**
 * One authenticated POST to tds-core-frontend-api's `/internal/mail/*`.
 *
 * Plain PHP streams, no HTTP client dependency: this service shares one PHP
 * process with the others in the gateway's in-process mode, and every shared
 * package is a version that can collide (tds-gateway-api#8).
 */
final class ServiceMailCall
{
    /** @param array<string,mixed> $payload */
    public static function post(
        string $frontendApiUrl,
        string $serviceToken,
        string $path,
        array $payload,
        float $timeoutSeconds,
        string $label,
    ): bool {
        if ($frontendApiUrl === '' || $serviceToken === '') {
            error_log("[tds-auth-api] {$label}: FRONTEND_API_URL or the service token is not set, no mail sent");
            return false;
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\n"
                    . "Authorization: Bearer {$serviceToken}\r\n",
                'content' => json_encode($payload),
                'timeout' => $timeoutSeconds,
                'ignore_errors' => true,
            ],
        ]);

        $url = rtrim($frontendApiUrl, '/') . $path;
        $result = @file_get_contents($url, false, $context);
        $status = self::statusOf($http_response_header ?? []);
        if ($result === false || $status < 200 || $status >= 300) {
            error_log("[tds-auth-api] {$label}: mail call to {$url} failed (HTTP {$status})");
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
