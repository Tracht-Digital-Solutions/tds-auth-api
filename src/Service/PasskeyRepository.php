<?php
declare(strict_types=1);

namespace Tds\AuthApi\Service;

/**
 * Registered WebAuthn credentials ("Passkeys"), one row per authenticator.
 *
 * Lookup is BY CREDENTIAL ID, not by user: a passkey sign-in carries no email —
 * the authenticator names the account. That is the whole point of the
 * discoverable-credential flow this service uses.
 */
interface PasskeyRepository
{
    /**
     * @return array{id:int, user_id:int, credential_id:string, public_key:string, sign_count:int, name:?string}|null
     */
    public function findByCredentialId(string $credentialId): ?array;

    /**
     * @return list<array{id:int, credential_id:string, name:?string, created_at:string, last_used_at:?string}>
     */
    public function listForUser(int $userId): array;

    /** Credential ids already registered to a user — the `excludeCredentials` list. */
    public function credentialIdsForUser(int $userId): array;

    public function store(int $userId, string $credentialId, string $publicKeyPem, int $signCount, ?string $name): void;

    public function touch(int $id, int $signCount): void;

    /** Delete one passkey, scoped to its owner so an id guess cannot delete someone else's. */
    public function deleteForUser(int $id, int $userId): bool;
}
