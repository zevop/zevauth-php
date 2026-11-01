<?php

declare(strict_types=1);

namespace ZevAuth\Exception;

/**
 * The backend API refused a request, or could not be reached.
 *
 * `$errorCode` is the API's code (`not_found`, `rate_limited`,
 * `organization_permission_required`, …), `request_failed` when the
 * response carried none, or `network_error` (status 0) when the request
 * never got an answer. `$requestId` is what ZevAuth support asks for.
 */
final class ApiException extends ZevAuthException
{
    public function __construct(
        string $message,
        string $errorCode,
        public readonly int $status,
        public readonly ?string $requestId = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, $errorCode, $previous);
    }
}
