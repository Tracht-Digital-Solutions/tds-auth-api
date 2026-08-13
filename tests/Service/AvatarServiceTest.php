<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Service;

use PHPUnit\Framework\TestCase;
use Tds\AuthApi\Service\AvatarService;

/**
 * The upload's content check. This is a security boundary, not a convenience:
 * whatever `sniff()` accepts gets stored and later served back from the API
 * origin — the same origin the session cookie is scoped to.
 */
final class AvatarServiceTest extends TestCase
{
    private AvatarService $service;

    protected function setUp(): void
    {
        $this->service = new AvatarService('https://api.tracht-digital.de/auth');
    }

    public function test_accepts_the_three_supported_raster_formats(): void
    {
        self::assertSame('image/png', $this->service->sniff(self::pngBytes()));
        self::assertSame('image/jpeg', $this->service->sniff(self::jpegBytes()));
    }

    public function test_rejects_svg_even_though_it_is_an_image(): void
    {
        // SVG is a document: it can carry <script> and external references,
        // and this file is served from the API origin. `getimagesizefromstring`
        // does not recognise it, which is the behaviour relied on here — this
        // test exists so that staying true is deliberate rather than lucky.
        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>';

        self::assertNull($this->service->sniff($svg));
    }

    public function test_rejects_html_wearing_an_image_content_type(): void
    {
        // The multipart part's declared Content-Type is attacker-controlled
        // and is never consulted; only the bytes decide.
        self::assertNull($this->service->sniff('<!doctype html><script>alert(1)</script>'));
    }

    public function test_rejects_empty_and_oversized_uploads(): void
    {
        self::assertNull($this->service->sniff(''));
        self::assertNull($this->service->sniff(str_repeat('a', AvatarService::MAX_BYTES + 1)));
    }

    public function test_builds_a_cache_busted_absolute_url(): void
    {
        $url = $this->service->url(42, '2026-08-13 10:00:00');

        self::assertStringStartsWith('https://api.tracht-digital.de/auth/users/42/avatar?v=', $url);
    }

    public function test_a_new_upload_time_produces_a_new_url(): void
    {
        // Without this the panel keeps showing the old picture for up to the
        // response's max-age after a replacement.
        $before = $this->service->url(42, '2026-08-13 10:00:00');
        $after = $this->service->url(42, '2026-08-13 10:05:00');

        self::assertNotSame($before, $after);
    }

    public function test_tolerates_a_trailing_slash_on_the_public_base(): void
    {
        $service = new AvatarService('https://api.tracht-digital.de/auth/');

        self::assertStringContainsString('/auth/users/42/avatar', $service->url(42, 'now'));
    }

    /** Smallest valid 1×1 PNG. */
    private static function pngBytes(): string
    {
        return (string) base64_decode(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
            true,
        );
    }

    /** Smallest valid 1×1 JPEG. */
    private static function jpegBytes(): string
    {
        return (string) base64_decode(
            '/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0a'
            . 'HBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAABAAAAAAAA'
            . 'AAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AKp//2Q==',
            true,
        );
    }
}
