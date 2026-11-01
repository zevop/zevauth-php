<?php

declare(strict_types=1);

namespace ZevAuth\Tests\Conformance;

use GuzzleHttp\Psr7\HttpFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ZevAuth\Auth;
use ZevAuth\Exception\AuthRefusedException;
use ZevAuth\Exception\VerifyException;
use ZevAuth\Tests\Support\FakeHttpClient;
use ZevAuth\Tests\Support\Fixtures;
use ZevAuth\TokenVerifier;
use ZevAuth\ZevAuth;

/**
 * tokens.json: every case through the verifier, getAuth, has() and
 * requireAuth(), with keys fetched through discovery as in production.
 */
final class TokensTest extends TestCase
{
    private const API = 'https://api.zevauth.test';

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function cases(): iterable
    {
        foreach (Fixtures::load('tokens.json')['cases'] as $case) {
            yield $case['name'] => [$case];
        }
    }

    /** @param array<string, mixed> $case */
    #[DataProvider('cases')]
    public function testVerification(array $case): void
    {
        [$verifier] = $this->verifierFor($case);

        $error = null;
        $claims = null;
        try {
            $claims = $verifier->verify($case['token']);
        } catch (VerifyException $e) {
            $error = $e->errorCode;
        }

        if ($case['expect']['ok']) {
            $this->assertNull($error, "{$case['name']}: refused with {$error}");
            $this->assertIsArray($claims);
        } else {
            $this->assertSame($case['expect']['error'], $error, $case['name']);
        }
    }

    /** @param array<string, mixed> $case */
    #[DataProvider('cases')]
    public function testAuthObjectHasAndRequireAuth(array $case): void
    {
        [$verifier] = $this->verifierFor($case);
        $bridge = new \ZevAuth\Bridge\SessionBridge($verifier, clock: Fixtures::clock(Fixtures::load('tokens.json')['now']));
        $auth = $bridge->readAuth('Bearer ' . $case['token'], []);

        foreach ($case['auth'] ?? [] as $field => $expected) {
            $this->assertSame($expected, $auth->{$field}, "{$case['name']}: auth.{$field}");
        }

        foreach ($case['has'] ?? [] as $check) {
            $this->assertSame(
                $check['result'],
                $auth->has($check['check']['role'] ?? null, $check['check']['permission'] ?? null),
                "{$case['name']}: has(" . json_encode($check['check']) . ')',
            );
        }

        foreach ($case['requireAuth'] ?? [] as $check) {
            $options = $check['options'];
            try {
                ZevAuth::check($auth, $options['allowPendingTasks'] ?? false, $options['requireMfa'] ?? false);
                $this->assertTrue($check['result']['ok'], "{$case['name']}: requireAuth should have refused");
            } catch (AuthRefusedException $e) {
                $this->assertFalse($check['result']['ok'], "{$case['name']}: requireAuth refused with {$e->errorCode}");
                $this->assertSame($check['result']['status'], $e->status);
                $this->assertSame($check['result']['code'], $e->errorCode);
                $this->assertSame($check['result']['code'], $e->toArray()['error']['code']);
            }
        }
        $this->addToAssertionCount(1);
    }

    /** @param array<string, mixed> $case */
    #[DataProvider('cases')]
    public function testLocalKeySet(array $case): void
    {
        if (isset($case['jwksAfterRefetch'])) {
            $this->markTestSkipped('A local key set never refetches; rotation is covered by the fetching verifier.');
        }
        $fixture = Fixtures::load('tokens.json');
        $verifier = new TokenVerifier(
            environmentId: $fixture['environmentId'],
            issuer: $fixture['issuer'],
            jwks: Fixtures::load($case['jwks']),
            clock: Fixtures::clock($fixture['now']),
        );

        try {
            $verifier->verify($case['token']);
            $this->assertTrue($case['expect']['ok'], $case['name']);
        } catch (VerifyException $e) {
            $this->assertSame($case['expect']['error'] ?? 'none', $e->errorCode, $case['name']);
        }
    }

    public function testUnknownKeysRefetchAtMostOncePerCooldown(): void
    {
        $case = array_values(array_filter(Fixtures::load('tokens.json')['cases'], static fn ($c) => $c['name'] === 'unknown_kid'))[0];
        [$verifier, $http, $jwksUri] = $this->verifierFor($case);

        for ($i = 0; $i < 5; $i++) {
            try {
                $verifier->verify($case['token']);
            } catch (VerifyException $e) {
                $this->assertSame('unknown_key', $e->errorCode);
            }
        }

        // One fetch for the cache, one refetch for the unknown kid, then the
        // cooldown holds.
        $this->assertSame(2, $http->countFor($jwksUri));
    }

    public function testDiscoveryAndKeysAreCachedAcrossCalls(): void
    {
        $case = Fixtures::load('tokens.json')['cases'][0];
        [$verifier, $http, $jwksUri] = $this->verifierFor($case);
        $verifier->verify($case['token']);
        $verifier->verify($case['token']);

        $this->assertSame(1, $http->countFor($jwksUri));
        $this->assertSame(1, $http->countFor(self::API . '/v1/env_test_fixture/.well-known/openid-configuration'));
    }

    public function testUnreachableKeysAreJwksUnavailableAndGetAuthStaysSignedOut(): void
    {
        $fixture = Fixtures::load('tokens.json');
        $http = (new FakeHttpClient())->queue('network');
        $verifier = new TokenVerifier(
            environmentId: $fixture['environmentId'],
            apiUrl: self::API,
            clock: Fixtures::clock($fixture['now']),
            httpClient: $http,
            requestFactory: new HttpFactory(),
        );

        try {
            $verifier->verify($fixture['cases'][0]['token']);
            $this->fail('expected jwks_unavailable');
        } catch (VerifyException $e) {
            $this->assertSame('jwks_unavailable', $e->errorCode);
        }

        $bridge = new \ZevAuth\Bridge\SessionBridge($verifier);
        $this->assertEquals(Auth::signedOut(), $bridge->readAuth('Bearer ' . $fixture['cases'][0]['token'], []));
    }

    /**
     * @param array<string, mixed> $case
     *
     * @return array{TokenVerifier, FakeHttpClient, string}
     */
    private function verifierFor(array $case): array
    {
        $fixture = Fixtures::load('tokens.json');
        $discovery = Fixtures::load('discovery.json');
        $jwks = Fixtures::load($case['jwks']);
        $after = isset($case['jwksAfterRefetch']) ? Fixtures::load($case['jwksAfterRefetch']) : $jwks;

        $http = (new FakeHttpClient())
            ->route(self::API . '/v1/env_test_fixture/.well-known/openid-configuration', [FakeHttpClient::json(200, $discovery)])
            ->route($discovery['jwks_uri'], [FakeHttpClient::json(200, $jwks), FakeHttpClient::json(200, $after)]);

        $verifier = new TokenVerifier(
            environmentId: $fixture['environmentId'],
            apiUrl: self::API,
            clockSkewSeconds: $fixture['clockSkewSeconds'],
            clock: Fixtures::clock($fixture['now']),
            httpClient: $http,
            requestFactory: new HttpFactory(),
        );

        return [$verifier, $http, $discovery['jwks_uri']];
    }
}
