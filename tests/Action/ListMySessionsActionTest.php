<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\ListMySessionsAction;
use Tds\AuthApi\Middleware\JwtAuthMiddleware;
use Tds\AuthApi\Tests\Support\FakeSessionRepository;

/**
 * The profile page's Sicherheit tab. The scoping is done in the repository
 * query, not in the action — a self-service caller must never be handed other
 * users' rows to filter.
 */
final class ListMySessionsActionTest extends TestCase
{
    private FakeSessionRepository $sessions;

    protected function setUp(): void
    {
        $this->sessions = new FakeSessionRepository();
        $future = time() + 3600;
        $this->sessions->record('mine-1', 7, false, $future, 5);
        $this->sessions->record('mine-2', 7, false, $future, 5);
        $this->sessions->record('theirs', 9, true, $future, 6);
    }

    public function test_returns_only_the_callers_sessions(): void
    {
        $body = $this->jsonBody($this->list());

        $ids = array_column($body['sessions'], 'jti');
        sort($ids);
        self::assertSame(['mine-1', 'mine-2'], $ids);
    }

    public function test_marks_the_session_making_the_request(): void
    {
        // Without this the "Abmelden" button on an unlabelled row is a coin
        // flip — every row looks the same to the person reading it.
        $body = $this->jsonBody($this->list());

        $current = array_values(array_filter($body['sessions'], fn (array $s) => $s['current']));
        self::assertCount(1, $current);
        self::assertSame('mine-1', $current[0]['jti']);
    }

    public function test_omits_revoked_and_expired_sessions(): void
    {
        $this->sessions->revoke('mine-2');
        $this->sessions->record('stale', 7, false, time() - 60, 5);

        $body = $this->jsonBody($this->list());

        self::assertSame(['mine-1'], array_column($body['sessions'], 'jti'));
    }

    public function test_a_tokenless_request_is_401(): void
    {
        self::assertSame(401, $this->list(uid: 0)->getStatusCode());
    }

    private function list(int $uid = 5): ResponseInterface
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', '/me/sessions')
            ->withAttribute(JwtAuthMiddleware::ATTR_CLAIMS, ['uid' => $uid, 'jti' => 'mine-1']);

        return (new ListMySessionsAction($this->sessions))($request, new Response());
    }

    /** @return array<string,mixed> */
    private function jsonBody(ResponseInterface $response): array
    {
        $response->getBody()->rewind();
        return json_decode($response->getBody()->getContents(), true);
    }
}
