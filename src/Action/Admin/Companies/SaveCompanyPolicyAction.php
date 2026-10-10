<?php
declare(strict_types=1);

namespace Tds\AuthApi\Action\Admin\Companies;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Tds\AuthApi\Service\AppUserRepository;
use Tds\AuthApi\Service\CompanyPolicyRepository;
use Tds\AuthApi\Service\SessionRepository;

/**
 * PUT /admin/companies/{companyId}/policy
 *
 * Body: `{maxUsers?: int|null, allowedPermissions?: string[]|null,
 * allowCustomGroups?: bool, allowCompanyAdmins?: bool}`. Absent keys keep their
 * current value.
 *
 * ### `allowCompanyAdmins` is the switch the whole delegated surface hangs on
 *
 * Off (and off is the default, including for a company with no policy row at
 * all): nobody inside the company can create or manage users or assign groups,
 * `/company/*` answers 403, and a membership's `is_company_admin` resolves to
 * false everywhere it is published. Turning it off revokes the company's
 * sessions for the same reason a narrowed ceiling does.
 *
 * ### `null` and `[]` are different answers
 *
 * `allowedPermissions: null` means "no ceiling"; `[]` means "may grant
 * nothing". Collapsing them would make locking a company down completely
 * unexpressible, so the null check happens before any cast.
 *
 * ### Lowering a ceiling takes effect immediately
 *
 * The ceiling is intersected when a token is issued, not only when a right is
 * granted — otherwise it would be a one-time gate and every already-assigned
 * group would keep out-granting it. So narrowing `allowedPermissions` really
 * does reduce what existing users can do, and their sessions are revoked to
 * make that happen now rather than within the hour.
 *
 * Gated by JwtAuthMiddleware(requireAdmin: true).
 */
final class SaveCompanyPolicyAction
{
    public function __construct(
        private readonly CompanyPolicyRepository $policies,
        private readonly AppUserRepository $users,
        private readonly SessionRepository $sessions,
    ) {
    }

    public function __invoke(
        ServerRequestInterface $request,
        Response $response,
        array $args = [],
    ): ResponseInterface {
        $companyId = (int) ($args['companyId'] ?? 0);
        if ($companyId <= 0) {
            return $this->json($response, 404, ['error' => 'Company not found']);
        }

        $body = (array) $request->getParsedBody();
        $fields = [];

        if (array_key_exists('maxUsers', $body)) {
            if ($body['maxUsers'] === null || $body['maxUsers'] === '') {
                $fields['maxUsers'] = null;
            } else {
                $max = (int) $body['maxUsers'];
                if ($max < 0) {
                    return $this->json($response, 422, ['error' => 'maxUsers must not be negative']);
                }
                $used = $this->policies->seatsUsed($companyId);
                if ($max < $used) {
                    // Refuse rather than silently allow an over-subscribed
                    // company: the alternative is a cap that is already
                    // violated, where the next create fails for a reason
                    // nobody set today.
                    return $this->json($response, 409, [
                        'error' => 'The company already has more users than that',
                        'code' => 'seats_in_use',
                        'used' => $used,
                    ]);
                }
                $fields['maxUsers'] = $max;
            }
        }

        $ceilingChanged = array_key_exists('allowedPermissions', $body);
        if ($ceilingChanged) {
            // null (no ceiling) vs [] (grant nothing) — see the class docblock.
            $fields['allowedPermissions'] = $body['allowedPermissions'] === null
                ? null
                : (array) $body['allowedPermissions'];
        }

        if (array_key_exists('allowCustomGroups', $body)) {
            $fields['allowCustomGroups'] = (bool) $body['allowCustomGroups'];
        }

        // Switching delegation off has to reach people the same way a narrowed
        // ceiling does: the `admin` flag rides in a signed token, so without a
        // revoke a company admin keeps administering for up to an hour after
        // the switch says they may not.
        $delegationChanged = array_key_exists('allowCompanyAdmins', $body)
            && (bool) $body['allowCompanyAdmins'] !== $this->policies->get($companyId)->allowCompanyAdmins;
        if (array_key_exists('allowCompanyAdmins', $body)) {
            $fields['allowCompanyAdmins'] = (bool) $body['allowCompanyAdmins'];
        }

        $policy = $this->policies->save($companyId, $fields);

        // A narrowed ceiling reduces what people may already do; make it real
        // now instead of up to an hour from now.
        $revoked = 0;
        if ($ceilingChanged || $delegationChanged) {
            foreach ($this->users->list($companyId) as $member) {
                $this->sessions->revokeAllForUser($member->id);
                $revoked++;
            }
        }

        return $this->json($response, 200, [
            'policy' => $policy->toArray(),
            'seatsUsed' => $this->policies->seatsUsed($companyId),
            'sessionsRevoked' => $revoked,
        ]);
    }

    /** @param array<string,mixed> $payload */
    private function json(Response $response, int $status, array $payload): ResponseInterface
    {
        $response->getBody()->write(json_encode($payload));

        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
