<?php

declare(strict_types=1);

namespace ZevAuth\Tests\Conformance;

use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ZevAuth\Api\Transport;
use ZevAuth\Exception\ApiException;
use ZevAuth\Exception\ConfigurationException;
use ZevAuth\Tests\Support\FakeHttpClient;
use ZevAuth\Tests\Support\Fixtures;
use ZevAuth\Version;
use ZevAuth\ZevAuthClient;

/** api-errors.json, plus the retry rule and the client's own checks. */
final class ApiErrorsTest extends TestCase
{
    /** @return iterable<string, array{array<string, mixed>}> */
    public static function cases(): iterable
    {
        foreach (Fixtures::load('api-errors.json')['cases'] as $case) {
            yield $case['name'] => [$case];
        }
    }

    /** @param array<string, mixed> $case */
    #[DataProvider('cases')]
    public function testErrorShape(array $case): void
    {
        $http = (new FakeHttpClient())->queue(self::response($case));
        $client = $this->client($http, maxRetries: 0);

        try {
            $client->users->get('user_1');
            $this->fail('expected an ApiException');
        } catch (ApiException $e) {
            $this->assertSame($case['expect']['code'], $e->errorCode);
            $this->assertSame($case['expect']['status'], $e->status);
            $this->assertSame($case['expect']['requestId'] ?? null, $e->requestId);
        }

        $this->assertSame($case['expect']['retry'], Transport::isRetryable($case['status']));
        if (isset($case['expect']['retryAfterSeconds'])) {
            $this->assertSame($case['expect']['retryAfterSeconds'] * 1000, Transport::retryAfterMs($case['headers']['retry-after']));
        }
    }

    /** @param array<string, mixed> $case */
    #[DataProvider('cases')]
    public function testRetriesOnlyWhatCertainlyDidNotRun(array $case): void
    {
        $http = (new FakeHttpClient())->queue(self::response($case), FakeHttpClient::json(200, ['id' => 'user_1']));
        $waits = [];
        $client = $this->client($http, maxRetries: 2, sleep: function (int $ms) use (&$waits): void {
            $waits[] = $ms;
        });

        if ($case['expect']['retry']) {
            $this->assertSame(['id' => 'user_1'], $client->users->get('user_1'));
            $this->assertCount(2, $http->requests);
            $this->assertSame([isset($case['expect']['retryAfterSeconds']) ? $case['expect']['retryAfterSeconds'] * 1000 : 200], $waits);
        } else {
            try {
                $client->users->get('user_1');
                $this->fail('expected an ApiException');
            } catch (ApiException) {
                $this->assertCount(1, $http->requests, "{$case['name']} must not be retried");
            }
        }
    }

    public function testNetworkFailuresAreRetriedThenReported(): void
    {
        $http = (new FakeHttpClient())->queue('network');
        $client = $this->client($http, maxRetries: 2);

        try {
            $client->users->get('user_1');
            $this->fail('expected network_error');
        } catch (ApiException $e) {
            $this->assertSame('network_error', $e->errorCode);
            $this->assertSame(0, $e->status);
        }
        $this->assertCount(3, $http->requests);
    }

    public function testRequestsCarryKeyUserAgentAndEncodedIds(): void
    {
        $http = (new FakeHttpClient())->queue(FakeHttpClient::json(200, ['data' => [], 'hasMore' => false, 'next' => null]));
        $client = $this->client($http);
        $client->users->list(limit: 10, metadata: ['plan' => 'pro']);
        $client->users->get('user/../x');
        $client->users->resetMfa('user_1', revokeSessions: true);

        $first = $http->requests[0];
        $this->assertSame('Bearer sk_test_fixture', $first->getHeaderLine('Authorization'));
        $this->assertSame('zevauth-php/' . Version::VERSION, $first->getHeaderLine('User-Agent'));
        $this->assertSame('limit=10&metadata%5Bplan%5D=pro', $first->getUri()->getQuery());
        $this->assertSame('/v1/users/user%2F..%2Fx', $http->requests[1]->getUri()->getPath());
        $this->assertSame('DELETE', $http->requests[2]->getMethod());
        $this->assertSame('revokeSessions=true', $http->requests[2]->getUri()->getQuery());
    }

    public function testIteratorFollowsCursors(): void
    {
        $http = (new FakeHttpClient())->queue(
            FakeHttpClient::json(200, ['data' => [['id' => 'u1'], ['id' => 'u2']], 'hasMore' => true, 'next' => 'cur_2']),
            FakeHttpClient::json(200, ['data' => [['id' => 'u3']], 'hasMore' => false, 'next' => null]),
        );
        $ids = array_map(static fn ($u) => $u['id'], iterator_to_array($this->client($http)->users->iterate(), false));

        $this->assertSame(['u1', 'u2', 'u3'], $ids);
        $this->assertSame('after=cur_2', $http->requests[1]->getUri()->getQuery());
    }

    public function testKeyChecksAtConstruction(): void
    {
        foreach (['' => 'missing_secret_key', 'pk_test_abc' => 'wrong_key_type'] as $key => $code) {
            try {
                new ZevAuthClient((string) $key, httpClient: new FakeHttpClient(), requestFactory: new HttpFactory(), streamFactory: new HttpFactory());
                $this->fail("expected {$code}");
            } catch (ConfigurationException $e) {
                $this->assertSame($code, $e->errorCode);
            }
        }
    }

    /** @param array<string, mixed> $case */
    private static function response(array $case): Response
    {
        $body = array_key_exists('bodyText', $case) ? $case['bodyText'] : ($case['body'] === null ? '' : json_encode($case['body']));

        return new Response($case['status'], $case['headers'], $body);
    }

    private function client(FakeHttpClient $http, int $maxRetries = 2, ?\Closure $sleep = null): ZevAuthClient
    {
        return new ZevAuthClient(
            'sk_test_fixture',
            apiUrl: 'https://api.zevauth.test',
            maxRetries: $maxRetries,
            httpClient: $http,
            requestFactory: new HttpFactory(),
            streamFactory: new HttpFactory(),
            sleep: $sleep ?? static function (int $ms): void {
            },
        );
    }
}
