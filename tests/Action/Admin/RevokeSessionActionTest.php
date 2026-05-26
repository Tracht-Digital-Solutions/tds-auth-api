<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Action\Admin;

use PHPUnit\Framework\TestCase;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;
use Tds\AuthApi\Action\Admin\RevokeSessionAction;
use Tds\AuthApi\Tests\Support\FakeSessionRepository;

final class RevokeSessionActionTest extends TestCase
{
    public function test_revokes_existing_session(): void
    {
        $sessions = new FakeSessionRepository();
        $sessions->record('jti-1', null, true, time() + 3600);

        $response = $this->dispatch($sessions, 'jti-1');

        self::assertSame(204, $response->getStatusCode());
        self::assertTrue($sessions->isRevoked('jti-1'));
    }

    public function test_unknown_jti_returns_204_idempotent(): void
    {
        $sessions = new FakeSessionRepository();

        $response = $this->dispatch($sessions, 'does-not-exist');

        self::assertSame(204, $response->getStatusCode());
        self::assertSame(['does-not-exist'], $sessions->revoked);
    }

    public function test_already_revoked_returns_204(): void
    {
        $sessions = new FakeSessionRepository();
        $sessions->record('jti-1', null, true, time() + 3600);
        $sessions->revoke('jti-1');

        $response = $this->dispatch($sessions, 'jti-1');

        self::assertSame(204, $response->getStatusCode());
    }

    public function test_empty_jti_returns_400(): void
    {
        $sessions = new FakeSessionRepository();
        $request = (new ServerRequestFactory())->createServerRequest('DELETE', '/admin/sessions/');

        $response = (new RevokeSessionAction($sessions))($request, new Response(), ['jti' => '']);

        self::assertSame(400, $response->getStatusCode());
    }

    private function dispatch(FakeSessionRepository $sessions, string $jti): \Psr\Http\Message\ResponseInterface
    {
        $request = (new ServerRequestFactory())->createServerRequest('DELETE', "/admin/sessions/{$jti}");
        return (new RevokeSessionAction($sessions))($request, new Response(), ['jti' => $jti]);
    }
}
