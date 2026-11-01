<?php

declare(strict_types=1);

namespace ZevAuth\Exception;

/**
 * A webhook delivery failed verification.
 *
 * `$errorCode` is `webhook_malformed_signature`,
 * `webhook_timestamp_out_of_range` or `webhook_signature_mismatch`.
 * Answer such a request with 400 and do nothing with it.
 */
final class WebhookException extends ZevAuthException
{
}
