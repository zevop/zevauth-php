<?php

declare(strict_types=1);

namespace ZevAuth;

use Http\Discovery\Psr17FactoryDiscovery;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\SimpleCache\CacheInterface;
use ZevAuth\Bridge\BridgeResult;
use ZevAuth\Bridge\SessionBridge;
use ZevAuth\Exception\AuthRefusedException;
use ZevAuth\Exception\VerifyException;

/**
 * Who is making a request, for any PHP app.
 *
 *     $zevauth = ZevAuth::create(environmentId: 'env_live_…', publishableKey: 'pk_live_…');
 *
 *     $auth = $zevauth->getAuthFromGlobals();        // plain PHP, WordPress
 *     $auth = $zevauth->getAuth($psr7Request);         // Slim, Mezzio, anything PSR-7
 *     $auth = $zevauth->requireAuth($psr7Request);     // throws AuthRefusedException
 *
 * The backend API client is separate (`ZevAuthClient`), because it needs
 * your secret key and most requests only need to know who is calling.
 */
final class ZevAuth
{
    private ?ResponseFactoryInterface $responseFactory;
    private ?StreamFactoryInterface $streamFactory;

    public function __construct(
        public readonly TokenVerifier $verifier,
        public readonly SessionBridge $bridge,
        /** Needed only to serve the handshake page. */
        public readonly ?string $publishableKey = null,
        /** Where the bridge endpoint is mounted, for the handshake page. */
        public readonly string $bridgePath = '/zevauth/session',
        public readonly ?string $uiScriptUrl = null,
        ?ResponseFactoryInterface $responseFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
    ) {
        $this->responseFactory = $responseFactory;
        $this->streamFactory = $streamFactory;
    }

    /**
     * The usual setup in one call.
     *
     * @param list<string>|null $allowedOrigins origins allowed to post to the bridge; default: the request's own
     * @param array<string, mixed>|null $jwks a local key set instead of fetching (needs `$issuer`)
     */
    public static function create(
        string $environmentId,
        ?string $publishableKey = null,
        string $apiUrl = TokenVerifier::DEFAULT_API_URL,
        ?CacheInterface $cache = null,
        ?ClockInterface $clock = null,
        ?ClientInterface $httpClient = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?string $issuer = null,
        ?array $jwks = null,
        int $clockSkewSeconds = 5,
        ?array $allowedOrigins = null,
        ?string $cookieDomain = null,
        bool $secureCookies = true,
        string $bridgePath = '/zevauth/session',
        string $handshakePath = SessionBridge::DEFAULT_HANDSHAKE_PATH,
        ?string $uiScriptUrl = null,
    ): self {
        $verifier = new TokenVerifier(
            environmentId: $environmentId,
            apiUrl: $apiUrl,
            issuer: $issuer,
            jwks: $jwks,
            clockSkewSeconds: $clockSkewSeconds,
            cache: $cache,
            clock: $clock,
            httpClient: $httpClient,
            requestFactory: $requestFactory,
        );
        $bridge = new SessionBridge($verifier, $allowedOrigins, $cookieDomain, $secureCookies, $handshakePath, $clock);

        return new self($verifier, $bridge, $publishableKey, $bridgePath, $uiScriptUrl);
    }

    /**
     * Verifies a token and returns its claims.
     *
     * @return array<string, mixed>
     *
     * @throws VerifyException
     */
    public function verifyToken(string $token): array
    {
        return $this->verifier->verify($token);
    }

    /**
     * Who made this request. Signed out (never an exception) when there is
     * no token or it does not verify.
     */
    public function getAuth(ServerRequestInterface $request): Auth
    {
        return $this->bridge->readAuth(
            $request->getHeaderLine('Authorization') ?: null,
            self::stringMap($request->getCookieParams()),
        );
    }

    /** `getAuth()` for plain PHP: reads `$_SERVER` and `$_COOKIE`. */
    public function getAuthFromGlobals(): Auth
    {
        $header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null;

        return $this->bridge->readAuth(is_string($header) ? $header : null, self::stringMap($_COOKIE));
    }

    /**
     * Like `getAuth()`, but refuses.
     *
     * @throws AuthRefusedException 401 `unauthorized`, 403 `session_task_pending` or 403 `mfa_required`
     */
    public function requireAuth(ServerRequestInterface $request, bool $allowPendingTasks = false, bool $requireMfa = false): Auth
    {
        return self::check($this->getAuth($request), $allowPendingTasks, $requireMfa);
    }

    /**
     * The `requireAuth()` rules applied to an `Auth` you already have.
     *
     * Pending tasks are refused unless allowed: only the routes that help
     * finish a task (set up two-step) should serve such a session.
     *
     * @throws AuthRefusedException
     */
    public static function check(Auth $auth, bool $allowPendingTasks = false, bool $requireMfa = false): Auth
    {
        if (!$auth->isSignedIn) {
            throw new AuthRefusedException('Sign in to continue.', 'unauthorized', 401);
        }
        if ($auth->pendingTasks !== [] && !$allowPendingTasks) {
            throw new AuthRefusedException(
                'Finish setting up your account to continue.',
                'session_task_pending',
                403,
                $auth->pendingTasks,
            );
        }
        if ($requireMfa && !$auth->isMfaVerified) {
            throw new AuthRefusedException('Two-step verification is required for this.', 'mfa_required', 403);
        }

        return $auth;
    }

    // ── Session bridge, PSR-7 ─────────────────────────────────────

    /** The bridge endpoint. Mount it at `bridgePath` for POST. */
    public function handleSessionBridge(ServerRequestInterface $request): ResponseInterface
    {
        $uri = $request->getUri();
        $origin = $uri->getScheme() . '://' . $uri->getHost() . ($uri->getPort() !== null ? ':' . $uri->getPort() : '');

        return $this->render($this->bridge->handle(
            $request->getMethod(),
            $request->getHeaderLine(SessionBridge::HEADER) ?: null,
            $request->getHeaderLine('Origin') ?: null,
            $origin,
            (string) $request->getBody(),
        ));
    }

    /**
     * Who is signed in, plus the response to send instead when the bridge
     * cookie has lapsed (`handshake` is null when the page should render).
     *
     * @return array{auth: Auth, handshake: ResponseInterface|null}
     */
    public function authenticateRequest(ServerRequestInterface $request): array
    {
        $auth = $this->getAuth($request);
        $uri = $request->getUri();
        $result = $this->bridge->handshakeFor(
            $auth,
            $request->getMethod(),
            $request->getHeaderLine('Accept') ?: null,
            $uri->getPath() . ($uri->getQuery() !== '' ? '?' . $uri->getQuery() : ''),
            $request->getQueryParams(),
        );

        return ['auth' => $auth, 'handshake' => $result === null ? null : $this->render($result)];
    }

    /** The handshake page. Mount it at the bridge's `handshakePath` for GET. */
    public function handshakePage(ServerRequestInterface $request): ResponseInterface
    {
        $redirect = $request->getQueryParams()['redirect_url'] ?? null;
        $html = SessionBridge::handshakeHtml(
            is_string($redirect) ? $redirect : null,
            $this->requirePublishableKey(),
            $this->bridgePath,
            $this->verifier->apiUrl === TokenVerifier::DEFAULT_API_URL ? null : $this->verifier->apiUrl,
            $this->uiScriptUrl,
        );

        return $this->responses()->createResponse(200)
            ->withHeader('Content-Type', 'text/html; charset=utf-8')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Referrer-Policy', 'same-origin')
            ->withBody($this->streams()->createStream($html));
    }

    /** Renders a bridge decision as a PSR-7 response. */
    public function render(BridgeResult $result): ResponseInterface
    {
        $response = $this->responses()->createResponse($result->status);
        foreach ($result->headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }
        foreach ($result->cookies as $cookie) {
            $response = $response->withAddedHeader('Set-Cookie', $cookie->toHeader());
        }
        if ($result->body !== null) {
            $response = $response
                ->withHeader('Content-Type', 'application/json')
                ->withBody($this->streams()->createStream(json_encode($result->body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)));
        }

        return $response;
    }

    private function requirePublishableKey(): string
    {
        if ($this->publishableKey === null || $this->publishableKey === '') {
            throw new Exception\ConfigurationException(
                'The handshake page needs your publishable key (pk_test_… or pk_live_…).',
                'missing_publishable_key',
            );
        }

        return $this->publishableKey;
    }

    private function responses(): ResponseFactoryInterface
    {
        return $this->responseFactory ??= Psr17FactoryDiscovery::findResponseFactory();
    }

    private function streams(): StreamFactoryInterface
    {
        return $this->streamFactory ??= Psr17FactoryDiscovery::findStreamFactory();
    }

    /**
     * @param array<mixed> $values
     *
     * @return array<string, string>
     */
    private static function stringMap(array $values): array
    {
        $out = [];
        foreach ($values as $key => $value) {
            if (is_string($value)) {
                $out[(string) $key] = $value;
            }
        }

        return $out;
    }
}
