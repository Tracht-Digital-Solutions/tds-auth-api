<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\AvatarRepository;

/**
 * GET /users/{id}/avatar
 *
 * **Deliberately unauthenticated.** A cross-origin `<img src>` sends no
 * credentials — the panel is on `management.`/`app.` and this service is on
 * `api.`, so a session-gated avatar simply would not render. The alternative
 * (inlining every avatar as a data URL through an authenticated JSON call)
 * would put the bytes in every `/me` response and defeat HTTP caching.
 *
 * What that exposes is a picture the person chose as their public
 * representation, which already appears on the public blog's author pages.
 * It does NOT confirm account existence beyond that: a user id with no
 * avatar and a user id that does not exist both answer 404.
 *
 * `?v=` is ignored by the handler — it exists so a replaced picture gets a
 * new URL rather than waiting out the max-age. Correctness still comes from
 * the ETag.
 */
final class ShowAvatarAction
{
    /** Short enough that a cleared avatar disappears quickly. */
    private const MAX_AGE = 300;

    public function __construct(private readonly AvatarRepository $avatars)
    {
    }

    public function __invoke(
        ServerRequestInterface $request,
        Response $response,
        array $args = [],
    ): ResponseInterface {
        $id = (int) ($args['id'] ?? 0);
        if ($id <= 0) {
            return $response->withStatus(404);
        }

        $meta = $this->avatars->meta($id);
        if ($meta === null) {
            return $response->withStatus(404);
        }

        // Weak ETag: the body is byte-identical for a given (user, updated_at),
        // and this lets a repeat visit skip pulling the blob out of the DB
        // entirely — meta() does not select `content`.
        $etag = sprintf('W/"%s"', md5($id . '|' . $meta['updated_at']));
        if (trim($request->getHeaderLine('If-None-Match')) === $etag) {
            return $response->withStatus(304)
                ->withHeader('ETag', $etag)
                ->withHeader('Cache-Control', 'public, max-age=' . self::MAX_AGE);
        }

        $avatar = $this->avatars->find($id);
        if ($avatar === null) {
            // Deleted between the two reads.
            return $response->withStatus(404);
        }

        $response->getBody()->write($avatar['content']);

        return $response
            ->withHeader('Content-Type', $avatar['mime_type'])
            ->withHeader('Content-Length', (string) strlen($avatar['content']))
            ->withHeader('ETag', $etag)
            ->withHeader('Cache-Control', 'public, max-age=' . self::MAX_AGE)
            // The bytes are attacker-supplied in the sense that any logged-in
            // user chose them. They are sniffed as a real PNG/JPEG/WebP on
            // upload, but this closes the door on a browser deciding to
            // reinterpret them as something scriptable.
            ->withHeader('X-Content-Type-Options', 'nosniff')
            ->withHeader('Content-Disposition', 'inline');
    }
}
