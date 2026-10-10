<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin\Groups;

/**
 * Shared normalisation for the group create/update payloads — used by the
 * platform routes and by the company-scoped ones, so a group created either way
 * is the same shape.
 */
final class GroupPayload
{
    /**
     * A stable, URL-safe slug.
     *
     * Derived from the name when none is given, because a slug is an
     * implementation detail nobody should have to invent — but it is stored,
     * referenced and never regenerated, which is why it is normalised hard
     * (lowercase, `[a-z0-9_-]`, collapsed separators) rather than trusted.
     */
    public static function slug(mixed $raw): string
    {
        $text = strtolower(trim((string) $raw));
        // Transliterate the German umlauts rather than dropping them, or
        // "Prüfung" and "Prufung" would collapse to different-looking slugs.
        $text = strtr($text, ['ä' => 'ae', 'ö' => 'oe', 'ü' => 'ue', 'ß' => 'ss']);
        $text = preg_replace('/[^a-z0-9]+/', '_', $text) ?? '';
        $text = trim($text, '_');

        return mb_substr($text, 0, 64);
    }

    public static function description(mixed $raw): ?string
    {
        $text = trim((string) ($raw ?? ''));

        return $text === '' ? null : mb_substr($text, 0, 255);
    }
}
