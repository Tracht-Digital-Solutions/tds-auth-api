<?php
declare(strict_types=1);

/**
 * Bootstraps an admin login (app_user with is_admin=1). Run once per
 * environment to create the first admin now that the shared ADMIN_TOKEN
 * paste-login is gone. Safe to re-run: an existing email is promoted to admin
 * + reactivated (password only changes when one is supplied).
 *
 * Usage:
 *   composer create-admin -- you@example.com [password]
 *   php bin/create-admin.php you@example.com [password]
 *
 * Requires the DB env vars (.env) and a migrated database (app_user must exist).
 * If no password is given, a strong one is generated and printed once.
 */

use Tds\AuthApi\Infrastructure\Database;
use Tds\AuthApi\Infrastructure\PdoAppUserRepository;
use Tds\AuthApi\Service\PasswordGenerator;

$root = dirname(__DIR__);
require_once $root . '/vendor/autoload.php';

if (file_exists($root . '/.env')) {
    Dotenv\Dotenv::createImmutable($root)->load();
}

$args = array_values(array_slice($argv, 1));
$email = strtolower(trim((string) ($args[0] ?? getenv('ADMIN_BOOTSTRAP_EMAIL') ?: '')));
$password = (string) ($args[1] ?? getenv('ADMIN_BOOTSTRAP_PASSWORD') ?: '');

if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
    fwrite(STDERR, "Usage: php bin/create-admin.php <email> [password]\n");
    exit(1);
}

$env = static function (string $key, string $default = ''): string {
    $v = $_ENV[$key] ?? false;
    if ($v === false) {
        $v = getenv($key);
    }
    return $v === false ? $default : (string) $v;
};

$pdo = Database::connect([
    'host' => $env('DB_HOST', '127.0.0.1'),
    'port' => $env('DB_PORT', '3306'),
    'name' => $env('DB_NAME', 'tds_auth'),
    'user' => $env('DB_USER', 'root'),
    'pass' => $env('DB_PASS', ''),
]);

$users = new PdoAppUserRepository($pdo);

$generated = false;
if ($password === '') {
    $password = (new PasswordGenerator())->generate(20);
    $generated = true;
} elseif (strlen($password) < 12) {
    fwrite(STDERR, "Password must be at least 12 characters.\n");
    exit(1);
}

$hash = password_hash($password, PASSWORD_ARGON2ID);
if ($hash === false) {
    fwrite(STDERR, "Hashing failed.\n");
    exit(2);
}

$existing = $users->findByEmail($email);
if ($existing !== null) {
    $fields = ['is_admin' => true, 'status' => 'active'];
    $users->update($existing->id, $fields);
    if ($args[1] ?? getenv('ADMIN_BOOTSTRAP_PASSWORD')) {
        $users->updatePassword($existing->id, $hash);
    }
    echo "Existing user {$email} promoted to admin (id {$existing->id}).\n";
    if ($generated) {
        echo "No password set (user already had one). Use reset-password if needed.\n";
    }
    exit(0);
}

$id = $users->create($email, $hash, null, true, null, [], 'active');
if ($generated) {
    // The generated password is temporary — force a change on first login.
    $users->update($id, ['must_change_password' => true]);
}
echo "Created admin user {$email} (id {$id}).\n";
if ($generated) {
    echo "Temporary password: {$password}\n";
    echo "Log in at the admin panel — you'll be prompted to set a new password.\n";
}
