<?php
declare(strict_types=1);

/**
 * Generates a fresh RS256 keypair into keys/private.pem and
 * keys/public.pem. Run once per environment (dev + prod) to
 * bootstrap the JWT signing key. The private key NEVER leaves the
 * machine where it was generated except via secure transport — paste
 * it into the production host .env (JWT_PRIVATE_KEY=) and into a password
 * manager, then delete keys/private.pem if you want zero on-disk
 * exposure.
 *
 * Usage:
 *   composer keygen
 */

$root = dirname(__DIR__);
$keysDir = $root . '/keys';
if (!is_dir($keysDir)) {
    mkdir($keysDir, 0700, true);
}

$privFile = $keysDir . '/private.pem';
$pubFile = $keysDir . '/public.pem';

if (file_exists($privFile)) {
    fwrite(STDERR, "keys/private.pem already exists — delete it first if you really mean to rotate.\n");
    exit(1);
}

$res = openssl_pkey_new([
    'private_key_bits' => 2048,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
]);
if ($res === false) {
    fwrite(STDERR, "openssl_pkey_new failed\n");
    exit(2);
}

if (!openssl_pkey_export($res, $privPem)) {
    fwrite(STDERR, "openssl_pkey_export failed\n");
    exit(3);
}
file_put_contents($privFile, $privPem);
chmod($privFile, 0600);

$details = openssl_pkey_get_details($res);
if ($details === false || !isset($details['key'])) {
    fwrite(STDERR, "openssl_pkey_get_details failed\n");
    exit(4);
}
file_put_contents($pubFile, $details['key']);
chmod($pubFile, 0644);

echo "Wrote {$privFile} (mode 600)\n";
echo "Wrote {$pubFile} (mode 644)\n\n";
echo "Next steps:\n";
echo "  1. Copy the private key contents into your local .env (JWT_PRIVATE_KEY=).\n";
echo "  2. Copy the same value into the production host ~/sites/api.tracht-digital.de/auth/shared/.env\n";
echo "  3. Save the keypair in a password manager (1Password, BitWarden) for disaster recovery.\n";
echo "  4. Commit keys/public.pem to the repo (it is intentionally tracked).\n";
echo "  5. Optionally rm keys/private.pem after step 1 — only the env var is needed at runtime.\n";
