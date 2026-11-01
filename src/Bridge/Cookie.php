<?php

declare(strict_types=1);

namespace ZevAuth\Bridge;

/**
 * A cookie the session bridge wants set (or cleared, with `maxAge` 0).
 *
 * Framework-neutral on purpose: the PSR-7 adapter turns it into a
 * `Set-Cookie` header, the Laravel integration into a Symfony cookie.
 */
final class Cookie
{
    public function __construct(
        public readonly string $name,
        public readonly string $value,
        public readonly int $maxAge,
        public readonly bool $secure = true,
        public readonly ?string $domain = null,
        public readonly string $path = '/',
        public readonly bool $httpOnly = true,
        public readonly string $sameSite = 'Lax',
    ) {
    }

    public function toHeader(): string
    {
        $parts = ["{$this->name}={$this->value}", "Path={$this->path}", "Max-Age={$this->maxAge}"];
        if ($this->httpOnly) {
            $parts[] = 'HttpOnly';
        }
        $parts[] = "SameSite={$this->sameSite}";
        if ($this->secure) {
            $parts[] = 'Secure';
        }
        if ($this->domain !== null) {
            $parts[] = "Domain={$this->domain}";
        }

        return implode('; ', $parts);
    }
}
