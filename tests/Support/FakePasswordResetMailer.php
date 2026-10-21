<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Support;

use Tds\AuthApi\Service\PasswordResetMailer;

final class FakePasswordResetMailer implements PasswordResetMailer
{
    /** @var list<array{email:string, name:?string, link:string, lang:string, validMinutes:int}> */
    public array $sent = [];

    public function __construct(public bool $delivers = true)
    {
    }

    public function send(string $email, ?string $name, string $link, string $lang, int $validMinutes): bool
    {
        $this->sent[] = compact('email', 'name', 'link', 'lang', 'validMinutes');
        return $this->delivers;
    }

    /** The raw token from the last mailed link. */
    public function lastToken(): string
    {
        $link = $this->sent[array_key_last($this->sent)]['link'];
        parse_str((string) parse_url($link, PHP_URL_QUERY), $query);
        return (string) $query['token'];
    }
}
