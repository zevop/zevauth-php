<?php

declare(strict_types=1);

namespace ZevAuth;

use Closure;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use ZevAuth\Api\Organizations;
use ZevAuth\Api\Transport;
use ZevAuth\Api\Users;
use ZevAuth\Exception\ConfigurationException;

/**
 * The ZevAuth backend API, with your secret key.
 *
 *     $zevauth = new ZevAuthClient(getenv('ZEVAUTH_SECRET_KEY'));
 *     $user = $zevauth->users->get('user_…');
 *
 * Server-side only. A secret key in a browser is a key anyone can use.
 */
final class ZevAuthClient
{
    public readonly Users $users;
    public readonly Organizations $organizations;

    /**
     * @param ClientInterface|null $httpClient any PSR-18 client; when omitted, Guzzle (if installed) with `$timeoutSeconds`, else whatever php-http/discovery finds
     * @param (Closure(int): void)|null $sleep for tests: waits the given milliseconds between retries
     */
    public function __construct(
        string $secretKey,
        string $apiUrl = TokenVerifier::DEFAULT_API_URL,
        float $timeoutSeconds = 15.0,
        int $maxRetries = 2,
        ?ClientInterface $httpClient = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
        ?Closure $sleep = null,
    ) {
        if ($secretKey === '') {
            throw new ConfigurationException(
                'ZevAuthClient needs your secret key (sk_test_… or sk_live_…). Find it in the ZevAuth console under API keys.',
                'missing_secret_key',
            );
        }
        if (str_starts_with($secretKey, 'pk_')) {
            throw new ConfigurationException(
                'That is a publishable key. The backend API needs your secret key (sk_test_… or sk_live_…).',
                'wrong_key_type',
            );
        }

        $transport = new Transport(
            rtrim($apiUrl, '/'),
            $secretKey,
            $httpClient ?? self::defaultClient($timeoutSeconds),
            $requestFactory ?? Psr17FactoryDiscovery::findRequestFactory(),
            $streamFactory ?? Psr17FactoryDiscovery::findStreamFactory(),
            max(0, $maxRetries),
            $sleep,
        );
        $this->users = new Users($transport);
        $this->organizations = new Organizations($transport);
    }

    private static function defaultClient(float $timeoutSeconds): ClientInterface
    {
        // PSR-18 has no timeout setting, so where Guzzle is available it is
        // built with one; other clients carry their own.
        if (class_exists(\GuzzleHttp\Client::class)) {
            return new \GuzzleHttp\Client(['timeout' => $timeoutSeconds, 'connect_timeout' => min(5.0, $timeoutSeconds), 'http_errors' => false]);
        }

        return Psr18ClientDiscovery::find();
    }
}
