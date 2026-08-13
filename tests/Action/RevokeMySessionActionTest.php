<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\RevokeMySessionAction;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Tests\Support\FakeSessionRepository;

/**
 * `SessionRepository::revoke()` revokes whatever jti it is handed and has no
 * notion of ownership, so this route is the only thing standing between a
 * logged-in user and every other user's sessions. Ownership is proved BEFORE
 * revoking, and a session that is not the caller's answers 404 rather than 403
 * — a 403 would confirm the jti exists.
 */
final class RevokeMySessionActionTest extends TestCase
{
    private FakeSessionRepository $sessions;

    protected function setUp(): void
    {
        $this->sessions = new FakeSessionRepository();
        $future = time() + 3600;
        $this->sessions->record('mine-1', 7, false, $future, 5);
        $this->sessions->record('mine-2', 7, false, $future, 5);
        $this->sessions->record('theirs', 9, false, $future, 6);
    }

    public function test_revokes_the_callers_own_session(): void
    {
        $response = $this->revoke('mine-2');

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['mine-2'], $this->sessions->revoked);
    }

    public function test_another_users_session_is_404_and_stays_alive(): void
    {
        $response = $this->revoke('theirs');

        self::assertSame(404, $response->getStatusCode());
        self::assertSame([], $this->sessions->revoked);
    }

    public function test_an_unknown_jti_is_indistinguishable_from_a_foreign_one(): void
    {
        // Both 404 with the same body — otherwise the route is an existence
        // oracle for other people's session ids.
        $foreign = $this->revoke('theirs');
        $unknown = $this->revoke('does-not-exist');

        self::assertSame($foreign->getStatusCode(), $unknown->getStatusCode());
        self::assertSame((string) $foreign->getBody(), (string) $unknown->getBody());
    }

    public function test_an_already_revoked_session_is_404(): void
    {
        $this->sessions->revoke('mine-1');
        $this->sessions->revoked = [];

        self::assertSame(404, $this->revoke('mine-1')->getStatusCode());
        self::assertSame([], $this->sessions->revoked);
    }

    public function test_an_expired_session_is_404(): void
    {
        $this->sessions->record('stale', 7, false, time() - 60, 5);

        self::assertSame(404, $this->revoke('stale')->getStatusCode());
    }

    public function test_revoking_the_current_session_is_allowed(): void
    {
        // That is just "log out", reached from the session list. The panel's
        // 401 backstop takes it from there.
        $response = $this->revoke('mine-1');

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['mine-1'], $this->sessions->revoked);
    }

    public function test_a_tokenless_request_is_401(): void
    {
        $response = $this->revoke('mine-1', uid: 0);

        self::assertSame(401, $response->getStatusCode());
        self::assertSame([], $this->sessions->revoked);
    }

    private function revoke(string $jti, int $uid = 5): ResponseInterface
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('DELETE', '/me/sessions/' . $jti)
            ->withAttribute(JwtAuthMiddleware::ATTR_CLAIMS, ['uid' => $uid, 'jti' => 'mine-1']);

        return (new RevokeMySessionAction($this->sessions))($request, new Response(), ['jti' => $jti]);
    }
}
