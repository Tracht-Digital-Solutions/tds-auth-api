<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

/**
 * Generates temporary passwords for admin-issued accounts and resets.
 * URL-safe alphabet (no ambiguous look-alikes), cryptographically random.
 */
final class PasswordGenerator
{
    private const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';

    public function generate(int $length = 16): string
    {
        $length = max(12, $length);
        $max = strlen(self::ALPHABET) - 1;
        $out = '';
        for ($i = 0; $i < $length; $i++) {
            $out .= self::ALPHABET[random_int(0, $max)];
        }
        return $out;
    }
}
