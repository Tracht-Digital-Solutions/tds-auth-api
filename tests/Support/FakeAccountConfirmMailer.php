<?php
declare(strict_types=1);

namespace Tds\AuthApi\Tests\Support;

use Tds\AuthApi\Service\AccountConfirmMailer;

final class FakeAccountConfirmMailer implements AccountConfirmMailer
{
    /** @var list<array{email:string, name:?string, link:string, lang:string, validHours:int}> */
    public array $sent = [];

    public function send(string $email, ?string $name, string $link, string $lang, int $validHours): bool
    {
        $this->sent[] = compact('email', 'name', 'link', 'lang', 'validHours');
        return true;
    }

    /** The raw token from the n-th mailed link (default: the last one). */
    public function token(?int $index = null): string
    {
        $link = $this->sent[$index ?? array_key_last($this->sent)]['link'];
        parse_str((string) parse_url($link, PHP_URL_QUERY), $query);
        return (string) $query['token'];
    }
}
