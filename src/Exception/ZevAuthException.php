<?php

declare(strict_types=1);

namespace ZevAuth\Exception;

use RuntimeException;

/**
 * Base for every error this library raises.
 *
 * Each one carries a stable string `$errorCode` from the shared contract
 * (`token_expired`, `rate_limited`, `webhook_signature_mismatch`, …), the
 * same codes every ZevAuth server library uses. Branch on the code, not
 * on the message: messages are written for people and can change.
 */
class ZevAuthException extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly string $errorCode,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
