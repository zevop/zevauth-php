<?php

declare(strict_types=1);

namespace ZevAuth;

/**
 * The session token in an `Authorization` header, if there is one.
 */
final class Bearer
{
    /**
     * `Bearer <token>` with the scheme exactly as written. Surrounding
     * whitespace is ignored; an empty token, a publishable key (`pk_…`) or
     * a secret key (`sk_…`) is not a session and reads as none.
     */
    public static function fromHeader(?string $header): ?string
    {
        if ($header === null || !str_starts_with($header, 'Bearer ')) {
            return null;
        }
        $token = trim(substr($header, 7));
        if ($token === '' || str_starts_with($token, 'pk_') || str_starts_with($token, 'sk_')) {
            return null;
        }

        return $token;
    }
}
