<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Support;

/**
 * Generates a fresh RSA keypair per test suite run. RS256 needs >= 2048
 * bits to be considered safe but we go 2048 even in tests to mirror the
 * real config.
 */
final class Keys
{
    public string $privatePem;
    public string $publicPem;

    public function __construct()
    {
        $res = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        if ($res === false) {
            throw new \RuntimeException('openssl_pkey_new failed: ' . openssl_error_string());
        }
        openssl_pkey_export($res, $priv);
        $details = openssl_pkey_get_details($res);
        $this->privatePem = (string) $priv;
        $this->publicPem = (string) ($details['key'] ?? '');
    }
}
