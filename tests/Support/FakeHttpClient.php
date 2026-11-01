<?php

declare(strict_types=1);

namespace ZevAuth\Tests\Support;

use GuzzleHttp\Psr7\Response;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * A PSR-18 client that answers from a script and records every request.
 *
 * Routes map a URL to a queue of responses; the last one repeats. A
 * response of `'network'` throws a network error instead.
 */
final class FakeHttpClient implements ClientInterface
{
    /** @var list<RequestInterface> */
    public array $requests = [];

    /** @var array<string, list<ResponseInterface|string>> */
    private array $routes = [];

    /** @var list<ResponseInterface|string> */
    private array $queue = [];

    /** @param list<ResponseInterface|string> $responses */
    public function route(string $url, array $responses): self
    {
        $this->routes[$url] = $responses;

        return $this;
    }

    /** Responses for any URL, in order. */
    public function queue(ResponseInterface|string ...$responses): self
    {
        $this->queue = array_values($responses);

        return $this;
    }

    public static function json(int $status, mixed $body, array $headers = []): Response
    {
        return new Response($status, $headers + ['Content-Type' => 'application/json'], json_encode($body, JSON_THROW_ON_ERROR));
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;
        $url = (string) $request->getUri();

        if (isset($this->routes[$url])) {
            $next = count($this->routes[$url]) > 1 ? array_shift($this->routes[$url]) : $this->routes[$url][0];
        } elseif ($this->queue !== []) {
            $next = count($this->queue) > 1 ? array_shift($this->queue) : $this->queue[0];
        } else {
            return new Response(404, [], 'not routed: ' . $url);
        }

        if ($next === 'network') {
            throw new class ($request) extends \RuntimeException implements NetworkExceptionInterface {
                public function __construct(private RequestInterface $request)
                {
                    parent::__construct('connection refused');
                }

                public function getRequest(): RequestInterface
                {
                    return $this->request;
                }
            };
        }

        return $next instanceof ResponseInterface ? $next : new Response(200, [], $next);
    }

    public function countFor(string $url): int
    {
        return count(array_filter($this->requests, static fn (RequestInterface $r) => (string) $r->getUri() === $url));
    }
}
