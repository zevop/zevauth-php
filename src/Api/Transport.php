<?php

declare(strict_types=1);

namespace ZevAuth\Api;

use Closure;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use ZevAuth\Exception\ApiException;
use ZevAuth\Version;

/**
 * Sends API requests, with the retry rule every ZevAuth library shares.
 *
 * Retried: 429, 502, 503, 504, and requests that never got an answer.
 * Never retried: any other 4xx, and 500. A 500 means the server ran and
 * failed, possibly after writing; retrying is how one `createUser`
 * becomes two.
 *
 * @internal
 */
final class Transport
{
    /** @var Closure(int): void */
    private Closure $sleep;

    /**
     * @param (Closure(int): void)|null $sleep waits the given milliseconds (injectable for tests)
     */
    public function __construct(
        private readonly string $apiUrl,
        private readonly string $secretKey,
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly int $maxRetries,
        ?Closure $sleep = null,
    ) {
        $this->sleep = $sleep ?? static function (int $ms): void {
            usleep($ms * 1000);
        };
    }

    /**
     * @param array<string, scalar|null> $query
     *
     * @return array<string, mixed>|null
     */
    public function request(string $method, string $path, array $query = [], mixed $body = null): ?array
    {
        $url = $this->apiUrl . $path . self::queryString($query);
        $last = null;
        $waitMs = null;

        for ($attempt = 0; $attempt <= $this->maxRetries; $attempt++) {
            if ($attempt > 0) {
                ($this->sleep)($waitMs ?? self::backoffMs($attempt));
            }
            $waitMs = null;

            $request = $this->requestFactory->createRequest($method, $url)
                ->withHeader('Authorization', "Bearer {$this->secretKey}")
                ->withHeader('Content-Type', 'application/json')
                ->withHeader('Accept', 'application/json')
                // So ZevAuth support can tell which library and version made a call.
                ->withHeader('User-Agent', 'zevauth-php/' . Version::VERSION);
            if ($body !== null) {
                $request = $request->withBody($this->streamFactory->createStream(json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)));
            }

            try {
                $response = $this->client->sendRequest($request);
            } catch (ClientExceptionInterface $e) {
                $last = new ApiException("Could not reach ZevAuth: {$e->getMessage()}", 'network_error', 0, null, $e);
                continue;
            }

            $status = $response->getStatusCode();
            if ($status === 204) {
                return null;
            }
            if ($status >= 200 && $status < 300) {
                $decoded = json_decode((string) $response->getBody(), true);

                return is_array($decoded) ? $decoded : null;
            }

            $error = self::errorFrom($response);
            if (self::isRetryable($status) && $attempt < $this->maxRetries) {
                $last = $error;
                $waitMs = self::retryAfterMs($response->getHeaderLine('Retry-After'));
                continue;
            }
            throw $error;
        }

        throw $last ?? new ApiException('Could not reach ZevAuth.', 'network_error', 0);
    }

    public static function isRetryable(int $status): bool
    {
        return in_array($status, [429, 502, 503, 504], true);
    }

    /** `Retry-After` in milliseconds, capped at 10 s; null when absent or unusable. */
    public static function retryAfterMs(string $header): ?int
    {
        if ($header === '' || !is_numeric($header) || (float) $header < 0) {
            return null;
        }

        return (int) min((float) $header * 1000, 10_000);
    }

    public static function errorFrom(ResponseInterface $response): ApiException
    {
        $status = $response->getStatusCode();
        $body = json_decode((string) $response->getBody(), true);
        $code = is_array($body) && is_string($body['error']['code'] ?? null) ? $body['error']['code'] : 'request_failed';
        $message = is_array($body) && is_string($body['error']['message'] ?? null)
            ? $body['error']['message']
            : (is_array($body) && is_string($body['message'] ?? null) ? $body['message'] : "ZevAuth returned {$status}.");
        $requestId = $response->getHeaderLine('x-request-id');

        return new ApiException($message, $code, $status, $requestId === '' ? null : $requestId);
    }

    private static function backoffMs(int $attempt): int
    {
        return (int) min(200 * 2 ** ($attempt - 1), 4000);
    }

    /**
     * @param array<string, scalar|null> $query
     */
    private static function queryString(array $query): string
    {
        $query = array_filter($query, static fn ($v) => $v !== null);
        foreach ($query as $key => $value) {
            if (is_bool($value)) {
                $query[$key] = $value ? 'true' : 'false';
            }
        }

        return $query === [] ? '' : '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }
}
