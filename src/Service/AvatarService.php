<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

/**
 * Validation and URL construction for profile pictures.
 *
 * Split out of the actions so the rules exist in exactly one place: the upload
 * route enforces them, and the test suite reads them from here rather than
 * re-stating the limits.
 */
final class AvatarService
{
    /**
     * 2 MiB. The panel downscales to 256×256 in a `<canvas>` before uploading,
     * so a legitimate avatar is ~20–60 KB; this is the ceiling for a client
     * that skipped that step, not the expected size.
     */
    public const MAX_BYTES = 2 * 1024 * 1024;

    /**
     * Raster formats only, and only ones every target browser decodes.
     *
     * **SVG is excluded on purpose.** It is a document, not an image: it can
     * carry `<script>` and external references, and this file is served from
     * the API origin where a stored XSS would sit next to the session cookie.
     */
    private const ALLOWED = [
        IMAGETYPE_PNG => 'image/png',
        IMAGETYPE_JPEG => 'image/jpeg',
        IMAGETYPE_WEBP => 'image/webp',
    ];

    /**
     * @param string $publicBase absolute public URL of this service, i.e. the
     *                           JWT issuer (`https://api.tracht-digital.de/auth`).
     *                           Reused deliberately rather than adding another
     *                           env var: it is already this service's public
     *                           base and is already written by all three env
     *                           writers (installer, docker entrypoint,
     *                           .env.example), which is exactly where a new
     *                           variable goes missing.
     */
    public function __construct(private readonly string $publicBase)
    {
    }

    /**
     * Sniff the bytes and return the MIME type to store, or null when the
     * upload is not an allowed image.
     *
     * The declared `Content-Type` of the part is ignored entirely — it is
     * attacker-controlled. `getimagesizefromstring` reads the actual header,
     * so a `.png`-labelled HTML document is rejected here rather than being
     * stored and later served back from our own origin.
     */
    public function sniff(string $bytes): ?string
    {
        if ($bytes === '' || strlen($bytes) > self::MAX_BYTES) {
            return null;
        }

        $info = @getimagesizefromstring($bytes);
        if ($info === false || !isset($info[2])) {
            return null;
        }

        return self::ALLOWED[$info[2]] ?? null;
    }

    /**
     * The public URL an `<img src>` points at, cache-busted by the row's
     * `updated_at` so replacing a picture is visible immediately instead of
     * sitting behind the response's max-age.
     */
    public function url(int $userId, string $updatedAt): string
    {
        return sprintf(
            '%s/users/%d/avatar?v=%d',
            rtrim($this->publicBase, '/'),
            $userId,
            strtotime($updatedAt) ?: time(),
        );
    }

    /** Human-readable limit for an error message. */
    public function maxBytes(): int
    {
        return self::MAX_BYTES;
    }
}
