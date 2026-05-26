<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action\Admin;

use PHPUnit\Framework\TestCase;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\Admin\ListSessionsAction;
use Tds\AuthApi\Tests\Support\FakeSessionRepository;

final class ListSessionsActionTest extends TestCase
{
    public function test_returns_empty_list_when_no_sessions(): void
    {
        $response = $this->dispatch(new FakeSessionRepository(), query: '');

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['sessions' => []], $this->jsonBody($response));
    }

    public function test_returns_active_sessions(): void
    {
        $sessions = new FakeSessionRepository();
        $sessions->record('jti-admin', null, true, time() + 3600);
        $sessions->record('jti-customer', 7, false, time() + 3600);

        $response = $this->dispatch($sessions, query: '');

        self::assertSame(200, $response->getStatusCode());
        $body = $this->jsonBody($response);
        self::assertCount(2, $body['sessions']);
        $jtis = array_column($body['sessions'], 'jti');
        self::assertContains('jti-admin', $jtis);
        self::assertContains('jti-customer', $jtis);
    }

    public function test_revoked_sessions_excluded(): void
    {
        $sessions = new FakeSessionRepository();
        $sessions->record('jti-active', null, true, time() + 3600);
        $sessions->record('jti-revoked', null, true, time() + 3600);
        $sessions->revoke('jti-revoked');

        $response = $this->dispatch($sessions, query: '');
        $body = $this->jsonBody($response);

        self::assertCount(1, $body['sessions']);
        self::assertSame('jti-active', $body['sessions'][0]['jti']);
    }

    public function test_expired_sessions_excluded(): void
    {
        $sessions = new FakeSessionRepository();
        $sessions->record('jti-future', null, true, time() + 3600);
        $sessions->record('jti-past', null, true, time() - 1);

        $response = $this->dispatch($sessions, query: '');
        $body = $this->jsonBody($response);

        self::assertCount(1, $body['sessions']);
        self::assertSame('jti-future', $body['sessions'][0]['jti']);
    }

    public function test_limit_query_param_clamped(): void
    {
        $sessions = new FakeSessionRepository();
        for ($i = 1; $i <= 5; $i++) {
            $sessions->record("jti-{$i}", null, true, time() + 3600);
        }

        $response = $this->dispatch($sessions, query: '?limit=2');
        $body = $this->jsonBody($response);
        self::assertCount(2, $body['sessions']);

        // limit=0 clamps to 1
        $response = $this->dispatch($sessions, query: '?limit=0');
        $body = $this->jsonBody($response);
        self::assertCount(1, $body['sessions']);

        // limit=9999 clamps to 500 (more than we seeded → 5)
        $response = $this->dispatch($sessions, query: '?limit=9999');
        $body = $this->jsonBody($response);
        self::assertCount(5, $body['sessions']);
    }

    private function dispatch(FakeSessionRepository $sessions, string $query): \Psr\Http\Message\ResponseInterface
    {
        $factory = new ServerRequestFactory();
        $request = $factory->createServerRequest('GET', '/admin/sessions' . $query);
        if ($query !== '') {
            parse_str(ltrim($query, '?'), $params);
            $request = $request->withQueryParams($params);
        }
        return (new ListSessionsAction($sessions))($request, new Response());
    }

    /** @return array<string,mixed> */
    private function jsonBody(\Psr\Http\Message\ResponseInterface $response): array
    {
        $response->getBody()->rewind();
        return json_decode($response->getBody()->getContents(), true);
    }
}
