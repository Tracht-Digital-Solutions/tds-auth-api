<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UploadedFileInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\AvatarRepository;
use Tds\AuthApi\Service\AvatarService;

/**
 * POST /me/avatar   (multipart/form-data, field `file`)
 *
 * Stores the caller's profile picture and points `app_user.avatar_url` at the
 * public read route.
 *
 * **No server-side resizing.** The prod host has no guaranteed `ext-gd`, and
 * the panel already downscales to 256×256 in a `<canvas>` before uploading, so
 * this validates and stores rather than transforms. An oversized upload is
 * rejected with a number the user can act on instead of being silently
 * re-encoded.
 *
 * Gated by JwtAuthMiddleware (any valid session) — a user may only ever
 * replace their OWN picture; the target is taken from the token, never from
 * the request.
 */
final class UploadAvatarAction
{
    public function __construct(
        private readonly AppUserRepository $users,
        private readonly AvatarRepository $avatars,
        private readonly AvatarService $service,
    ) {
    }

    public function __invoke(ServerRequestInterface $request, Response $response): ResponseInterface
    {
        /** @var array<string,mixed> $claims */
        $claims = (array) $request->getAttribute(JwtAuthMiddleware::ATTR_CLAIMS, []);
        $uid = isset($claims['uid']) && is_int($claims['uid']) ? $claims['uid'] : 0;

        $user = $uid > 0 ? $this->users->findById($uid) : null;
        if ($user === null) {
            return $this->json($response, 401, ['error' => 'User not found']);
        }

        $file = $request->getUploadedFiles()['file'] ?? null;
        if (!$file instanceof UploadedFileInterface) {
            return $this->json($response, 400, ['error' => 'file (multipart) required']);
        }
        if ($file->getError() !== UPLOAD_ERR_OK) {
            // Covers the PHP-level ini limits too (post_max_size etc.), which
            // otherwise surface as an empty, confusing 400.
            return $this->json($response, 400, ['error' => 'Upload failed']);
        }

        $size = $file->getSize();
        if ($size !== null && $size > $this->service->maxBytes()) {
            // Checked before reading so an oversized body is not pulled into
            // memory just to be rejected.
            return $this->json($response, 413, [
                'error' => 'Image too large',
                'maxBytes' => $this->service->maxBytes(),
            ]);
        }

        $bytes = (string) $file->getStream();

        // The declared Content-Type is ignored — see AvatarService::sniff().
        $mime = $this->service->sniff($bytes);
        if ($mime === null) {
            return $this->json($response, 422, [
                'error' => 'Unsupported image. Allowed: PNG, JPEG, WebP.',
                'maxBytes' => $this->service->maxBytes(),
            ]);
        }

        $this->avatars->put($uid, $bytes, $mime);

        $meta = $this->avatars->meta($uid);
        $url = $this->service->url($uid, $meta['updated_at'] ?? 'now');
        $this->users->update($uid, ['avatar_url' => $url]);

        return $this->json($response, 200, ['avatarUrl' => $url, 'sizeBytes' => strlen($bytes)]);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
