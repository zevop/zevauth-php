<?php

declare(strict_types=1);

namespace ZevAuth;

use Firebase\JWT\JWK;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\SimpleCache\CacheInterface;
use Throwable;
use ZevAuth\Exception\ConfigurationException;
use ZevAuth\Exception\VerifyException;
use ZevAuth\Internal\MemoryCache;
use ZevAuth\Internal\SystemClock;

/**
 * Verifies ZevAuth session tokens.
 *
 * ── The checks, in order ──────────────────────────────────────────
 * Shape, then algorithm, then key, then signature, then issuer, audience
 * and time. The algorithm is checked before any key is touched and only
 * RS256 is accepted: a token never chooses how it is verified, which is
 * what defeats `alg: none` and the HS256-with-the-public-key trick.
 *
 * ── Keys ──────────────────────────────────────────────────────────
 * The issuer comes from the environment's discovery document, never from
 * `apiUrl`: they may differ (local development, self-hosting). The key
 * set is cached for at most ten minutes. A token signed by a key we have
 * not seen triggers one refetch, so a rotation is picked up at once; a
 * cooldown stops a stream of made-up `kid`s from turning into a stream of
 * fetches. Both live in the PSR-16 cache so they hold across PHP-FPM
 * requests when the cache is shared.
 *
 * firebase/php-jwt converts the published JWKs into keys. Verification
 * itself is done here, because the contract fixes the order of the checks
 * and the error code each one produces.
 */
final class TokenVerifier
{
    public const DEFAULT_API_URL = 'https://api.zevauth.net';

    public readonly string $apiUrl;
    private readonly CacheInterface $cache;
    private readonly ClockInterface $clock;
    private ?ClientInterface $httpClient;
    private ?RequestFactoryInterface $requestFactory;

    /** @var array<string, mixed>|null the local key set, when one was given */
    private readonly ?array $localJwks;

    private ?string $issuer;

    /**
     * @param string $environmentId the environment's public id (`env_test_…` / `env_live_…`); tokens for any other environment are refused
     * @param array<string, mixed>|null $jwks a key set to use instead of fetching (tests, air-gapped servers); needs `$issuer`
     */
    public function __construct(
        public readonly string $environmentId,
        string $apiUrl = self::DEFAULT_API_URL,
        ?string $issuer = null,
        ?array $jwks = null,
        public readonly int $clockSkewSeconds = 5,
        ?CacheInterface $cache = null,
        ?ClockInterface $clock = null,
        ?ClientInterface $httpClient = null,
        ?RequestFactoryInterface $requestFactory = null,
        public readonly int $jwksMaxAgeSeconds = 600,
        public readonly int $refetchCooldownSeconds = 30,
    ) {
        if ($environmentId === '') {
            throw new ConfigurationException(
                'ZevAuth needs your environment id (env_test_… or env_live_…) to verify tokens. Find it in the ZevAuth console under API keys.',
                'missing_environment_id',
            );
        }
        if ($jwks !== null && ($issuer === null || $issuer === '')) {
            throw new ConfigurationException(
                'A local key set needs the issuer too, since there is no discovery document to read it from.',
                'missing_issuer',
            );
        }
        $this->apiUrl = rtrim($apiUrl, '/');
        $this->issuer = $issuer;
        $this->localJwks = $jwks;
        $this->cache = $cache ?? new MemoryCache();
        $this->clock = $clock ?? new SystemClock();
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
    }

    /**
     * Verifies a token and returns its claims.
     *
     * @return array<string, mixed>
     *
     * @throws VerifyException with one of the contract's codes
     */
    public function verify(string $token): array
    {
        // 1. Shape.
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw self::refuse('malformed_token', 'That is not a session token.');
        }
        [$headerB64, $payloadB64, $signatureB64] = $parts;
        $header = self::decodeJson($headerB64);
        $claims = self::decodeJson($payloadB64);
        if ($header === null || $claims === null) {
            throw self::refuse('malformed_token', 'That is not a session token.');
        }

        // 2. Algorithm, before any key is looked at. An unsigned token
        // (`alg: none`, empty signature) is named for what it is here rather
        // than dismissed as malformed.
        if (($header['alg'] ?? null) !== 'RS256') {
            throw self::refuse('unsupported_algorithm', 'Session tokens are signed with RS256 only.');
        }
        $signature = self::base64UrlDecode($signatureB64);
        if ($signature === null) {
            throw self::refuse('malformed_token', 'That is not a session token.');
        }

        // 3. Key.
        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || $kid === '') {
            throw self::refuse('unknown_key', 'The token names no signing key.');
        }
        $key = $this->keyFor($kid);

        // 4. Signature.
        $verified = openssl_verify("{$headerB64}.{$payloadB64}", $signature, $key, OPENSSL_ALGO_SHA256);
        if ($verified !== 1) {
            throw self::refuse('invalid_signature', 'The token signature does not verify.');
        }

        // Claims must have the types the contract states, or the token is
        // not one we minted.
        foreach (['iat', 'nbf', 'exp'] as $name) {
            if (array_key_exists($name, $claims) && !is_int($claims[$name]) && !is_float($claims[$name])) {
                throw self::refuse('malformed_token', "The {$name} claim is not a number.");
            }
        }
        if (!is_string($claims['sub'] ?? null)) {
            throw self::refuse('malformed_token', 'The token has no subject.');
        }

        // 5. Issuer.
        if (($claims['iss'] ?? null) !== $this->issuer()) {
            throw self::refuse('invalid_issuer', 'The token was not issued for this environment.');
        }

        // 6. Audience. Not optional: it is what stops a test token working
        // on a live route.
        $aud = $claims['aud'] ?? null;
        $audiences = is_array($aud) ? $aud : [$aud];
        if (!in_array($this->environmentId, $audiences, true)) {
            throw self::refuse('invalid_audience', 'The token belongs to another environment.');
        }

        // 7. Time, with skew.
        $now = $this->clock->now()->getTimestamp();
        if (isset($claims['exp']) && $now > $claims['exp'] + $this->clockSkewSeconds) {
            throw self::refuse('token_expired', 'The session token has expired.');
        }
        if (isset($claims['nbf']) && $now < $claims['nbf'] - $this->clockSkewSeconds) {
            throw self::refuse('token_not_yet_valid', 'The session token is not valid yet.');
        }

        return $claims;
    }

    /** The issuer tokens must carry, read from discovery when not given. */
    public function issuer(): string
    {
        if ($this->issuer !== null) {
            return $this->issuer;
        }
        $cacheKey = $this->cacheKey('issuer');
        $cached = $this->cache->get($cacheKey);
        if (is_string($cached) && $cached !== '') {
            return $this->issuer = $cached;
        }

        $discovery = $this->fetchJson("{$this->apiUrl}/v1/" . rawurlencode($this->environmentId) . '/.well-known/openid-configuration');
        $issuer = $discovery['issuer'] ?? null;
        if (!is_string($issuer) || $issuer === '') {
            throw self::refuse('jwks_unavailable', 'The discovery document has no issuer.');
        }
        if (is_string($discovery['jwks_uri'] ?? null)) {
            $this->cache->set($this->cacheKey('jwks_uri'), $discovery['jwks_uri'], 86400);
        }
        // Discovery does not change for an environment; a day keeps a shared
        // cache honest without a fetch per request.
        $this->cache->set($cacheKey, $issuer, 86400);

        return $this->issuer = $issuer;
    }

    /**
     * @return \OpenSSLAsymmetricKey
     */
    private function keyFor(string $kid): mixed
    {
        if ($this->localJwks !== null) {
            return $this->findKey($this->localJwks, $kid)
                ?? throw self::refuse('unknown_key', 'No key with that id in the key set.');
        }

        $keys = $this->cache->get($this->cacheKey('jwks'));
        if (!is_array($keys)) {
            $keys = $this->fetchKeys();
        }
        $key = $this->findKey($keys, $kid);
        if ($key !== null) {
            return $key;
        }

        // An unknown key: perhaps a rotation. Refetch once, unless we did so
        // moments ago.
        $cooldownKey = $this->cacheKey('refetched_at');
        $last = $this->cache->get($cooldownKey);
        $now = $this->clock->now()->getTimestamp();
        if (is_int($last) && $now - $last < $this->refetchCooldownSeconds) {
            throw self::refuse('unknown_key', 'No key with that id in the key set.');
        }
        $this->cache->set($cooldownKey, $now, $this->refetchCooldownSeconds);

        return $this->findKey($this->fetchKeys(), $kid)
            ?? throw self::refuse('unknown_key', 'No key with that id in the key set.');
    }

    /**
     * @return array<string, mixed>
     */
    private function fetchKeys(): array
    {
        $uri = $this->cache->get($this->cacheKey('jwks_uri'));
        if (!is_string($uri)) {
            $this->issuer();
            $uri = $this->cache->get($this->cacheKey('jwks_uri'));
        }
        if (!is_string($uri)) {
            $uri = "{$this->apiUrl}/v1/" . rawurlencode($this->environmentId) . '/.well-known/jwks.json';
        }
        $jwks = $this->fetchJson($uri);
        if (!is_array($jwks['keys'] ?? null)) {
            throw self::refuse('jwks_unavailable', 'The key set has no keys.');
        }
        $this->cache->set($this->cacheKey('jwks'), $jwks, $this->jwksMaxAgeSeconds);

        return $jwks;
    }

    /**
     * @param array<string, mixed> $jwks
     *
     * @return \OpenSSLAsymmetricKey|null
     */
    private function findKey(array $jwks, string $kid): mixed
    {
        foreach (is_array($jwks['keys'] ?? null) ? $jwks['keys'] : [] as $jwk) {
            if (!is_array($jwk) || ($jwk['kid'] ?? null) !== $kid || ($jwk['kty'] ?? null) !== 'RSA') {
                continue;
            }
            try {
                $material = JWK::parseKey($jwk, 'RS256')?->getKeyMaterial();
            } catch (Throwable) {
                return null;
            }
            if ($material instanceof \OpenSSLAsymmetricKey) {
                return $material;
            }
            if (is_string($material)) {
                $parsed = openssl_pkey_get_public($material);

                return $parsed === false ? null : $parsed;
            }
        }

        return null;
    }

    /**
     * @return array<string, mixed>
     */
    private function fetchJson(string $url): array
    {
        try {
            $client = $this->httpClient ??= Psr18ClientDiscovery::find();
            $factory = $this->requestFactory ??= Psr17FactoryDiscovery::findRequestFactory();
            $response = $client->sendRequest($factory->createRequest('GET', $url)->withHeader('Accept', 'application/json'));
        } catch (Throwable $e) {
            throw new VerifyException("Could not fetch {$url}: {$e->getMessage()}", 'jwks_unavailable', $e);
        }
        if ($response->getStatusCode() !== 200) {
            throw self::refuse('jwks_unavailable', "Fetching {$url} returned {$response->getStatusCode()}.");
        }
        $data = json_decode((string) $response->getBody(), true);
        if (!is_array($data)) {
            throw self::refuse('jwks_unavailable', "{$url} did not return JSON.");
        }

        return $data;
    }

    private function cacheKey(string $what): string
    {
        // PSR-16 keys may not contain {}()/\@: so the inputs are hashed.
        return 'zevauth.' . $what . '.' . sha1($this->apiUrl . '|' . $this->environmentId);
    }

    /**
     * @return array<string, mixed>|null
     */
    private static function decodeJson(string $segment): ?array
    {
        $raw = self::base64UrlDecode($segment);
        if ($raw === null) {
            return null;
        }
        $data = json_decode($raw, true);

        return is_array($data) && !array_is_list($data) ? $data : null;
    }

    private static function base64UrlDecode(string $segment): ?string
    {
        if ($segment === '' || preg_match('/[^A-Za-z0-9_-]/', $segment) === 1) {
            return null;
        }
        $decoded = base64_decode(strtr($segment, '-_', '+/') . str_repeat('=', (4 - strlen($segment) % 4) % 4), true);

        return $decoded === false ? null : $decoded;
    }

    private static function refuse(string $code, string $message): VerifyException
    {
        return new VerifyException($message, $code);
    }
}
