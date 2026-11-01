<?php

declare(strict_types=1);

namespace ZevAuth\Bridge;

/**
 * What the session bridge decided: a status, an optional JSON body, the
 * cookies to set and any extra headers. Adapters render it as a response
 * in whatever framework the app uses.
 */
final class BridgeResult
{
    /**
     * @param array<string, mixed>|null $body JSON body, or null for none
     * @param list<Cookie> $cookies
     * @param array<string, string> $headers
     */
    public function __construct(
        public readonly int $status,
        public readonly ?array $body = null,
        public readonly array $cookies = [],
        public readonly array $headers = [],
    ) {
    }

    /** The `code` of an error body, or null. */
    public function errorCode(): ?string
    {
        $code = $this->body['error']['code'] ?? null;

        return is_string($code) ? $code : null;
    }
}
