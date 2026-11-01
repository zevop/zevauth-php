<?php

declare(strict_types=1);

namespace ZevAuth\Exception;

/**
 * A session token was refused.
 *
 * `$errorCode` is one of: `malformed_token`, `unsupported_algorithm`,
 * `unknown_key`, `invalid_signature`, `invalid_issuer`,
 * `invalid_audience`, `token_expired`, `token_not_yet_valid`,
 * `jwks_unavailable`.
 *
 * Only the low-level verifier raises this. `getAuth()` turns every one of
 * them into "nobody is signed in", because a page deciding what to render
 * must not crash when a session lapses.
 */
final class VerifyException extends ZevAuthException
{
}
