<?php

declare(strict_types=1);

namespace ZevAuth\Bridge;

use Psr\Clock\ClockInterface;
use ZevAuth\Auth;
use ZevAuth\Bearer;
use ZevAuth\Exception\VerifyException;
use ZevAuth\Internal\SystemClock;
use ZevAuth\TokenVerifier;

/**
 * Sessions for server-rendered pages.
 *
 * ── Why this exists ───────────────────────────────────────────────
 * A browser asking for a page sends no `Authorization` header, so a PHP
 * page could not tell who was signed in. With `sessionBridge: { url }` in
 * the browser SDK, every new access token is posted to an endpoint on
 * your own site, which keeps it in an HttpOnly cookie. Pages read that.
 *
 * ── Why the server never refreshes ────────────────────────────────
 * ZevAuth refresh tokens rotate on every use, and one used twice ends the
 * whole session as stolen. A server refreshing alongside the browser
 * would race it and sign the person out. So the refresh token stays in
 * the browser, and only short-lived access tokens reach this cookie.
 * When the cookie lapses, a page sends the browser through a one-hop
 * handshake that refreshes in the browser and comes straight back.
 *
 * This class works on plain values (method, headers, body, cookies), so
 * the PSR-7 helpers on `ZevAuth`, plain PHP and the Laravel integration
 * all share it.
 */
final class SessionBridge
{
    public const HEADER = 'x-zevauth-bridge';
    public const HANDSHAKE_MARKER = '__zevauth_handshake';
    public const DEFAULT_HANDSHAKE_PATH = '/zevauth/handshake';
    public const DEFAULT_UI_SCRIPT = 'https://cdn.jsdelivr.net/npm/@zevauth/ui@0/dist/zevauth-ui.global.js';

    private const CLIENT_COOKIE_SECONDS = 30 * 24 * 60 * 60;

    private readonly ClockInterface $clock;

    /**
     * @param list<string>|null $allowedOrigins origins that may post sessions; default: the request's own origin
     * @param string|null $cookieDomain share the cookie with subdomains (switches to `__Secure-` names)
     * @param bool $secure false only for plain-http local development
     */
    public function __construct(
        private readonly TokenVerifier $verifier,
        public readonly ?array $allowedOrigins = null,
        public readonly ?string $cookieDomain = null,
        public readonly bool $secure = true,
        public readonly string $handshakePath = self::DEFAULT_HANDSHAKE_PATH,
        ?ClockInterface $clock = null,
    ) {
        $this->clock = $clock ?? new SystemClock();
    }

    /**
     * @return array{session: string, client: string}
     */
    public function cookieNames(): array
    {
        $prefix = !$this->secure ? '' : ($this->cookieDomain !== null ? '__Secure-' : '__Host-');

        return ['session' => "{$prefix}zevauth_session", 'client' => "{$prefix}zevauth_client"];
    }

    /**
     * The bridge endpoint: verify a posted token and keep it in a cookie.
     *
     * @param string|null $bridgeHeader the `x-zevauth-bridge` header
     * @param string|null $origin the `Origin` header
     * @param string $requestOrigin this request's own origin, e.g. `https://app.example.com`
     */
    public function handle(
        string $method,
        ?string $bridgeHeader,
        ?string $origin,
        string $requestOrigin,
        string $rawBody,
    ): BridgeResult {
        if (strtoupper($method) !== 'POST') {
            return self::error(405, 'method_not_allowed', 'The session bridge accepts POST only.', headers: ['Allow' => 'POST']);
        }
        // The header and the origin check together stop login CSRF: a page
        // elsewhere posting its own valid token to sign the visitor in as
        // somebody else.
        if ($bridgeHeader !== '1') {
            return self::error(403, 'bridge_header_missing', 'Send the x-zevauth-bridge: 1 header. The ZevAuth browser SDK does this for you.');
        }
        $allowed = $this->allowedOrigins ?? [$requestOrigin];
        if ($origin !== null && $origin !== '' && !in_array($origin, $allowed, true)) {
            return self::error(403, 'bridge_origin_not_allowed', "{$origin} may not post sessions here. Add it to allowedOrigins.");
        }

        $body = json_decode($rawBody, true);
        if (!is_array($body)) {
            return self::error(400, 'invalid_request', 'Expected a JSON body: { "token": string | null }.');
        }
        $token = $body['token'] ?? null;
        if ($token === null || $token === '') {
            return new BridgeResult(204, cookies: $this->clearCookies(), headers: ['Cache-Control' => 'no-store']);
        }
        if (!is_string($token)) {
            return self::error(400, 'invalid_request', '`token` must be a string or null.');
        }

        try {
            $claims = $this->verifier->verify($token);
        } catch (VerifyException $e) {
            // A refused token also ends whatever was there, so a stale cookie
            // never outlives a refusal.
            return new BridgeResult(
                401,
                ['error' => ['code' => 'unauthorized', 'message' => 'That session token was refused.', 'reason' => $e->errorCode]],
                $this->clearCookies(),
                ['Cache-Control' => 'no-store'],
            );
        }

        $now = $this->clock->now()->getTimestamp();
        $exp = is_numeric($claims['exp'] ?? null) ? (int) $claims['exp'] : $now;
        $names = $this->cookieNames();

        return new BridgeResult(204, cookies: [
            // The access token until it expires. Never the refresh token.
            $this->cookie($names['session'], $token, max(0, $exp - $now)),
            $this->cookie($names['client'], '1', self::CLIENT_COOKIE_SECONDS),
        ], headers: ['Cache-Control' => 'no-store']);
    }

    /**
     * Who is signed in, from the `Authorization` header or the bridge
     * cookie. Never raises for a missing or bad token.
     *
     * @param array<string, string> $cookies the request's cookies by name
     */
    public function readAuth(?string $authorization, array $cookies): Auth
    {
        $header = Bearer::fromHeader($authorization);
        $names = $this->cookieNames();
        $cookieToken = $cookies[$names['session']] ?? null;
        $token = $header ?? (is_string($cookieToken) && $cookieToken !== '' ? $cookieToken : null);
        $hasClient = ($cookies[$names['client']] ?? null) === '1';

        if ($token === null) {
            return Auth::signedOut(needsHandshake: $header === null && $hasClient);
        }
        try {
            return Auth::fromClaims($this->verifier->verify($token));
        } catch (VerifyException $e) {
            $expired = $e->errorCode === 'token_expired';

            return Auth::signedOut(needsHandshake: $header === null && ($expired || $hasClient));
        }
    }

    /**
     * What to do about a lapsed cookie: null to carry on, or a response to
     * send instead (a redirect into the handshake for a page, a 401 for
     * anything else).
     *
     * @param string $pathWithQuery the request's path and query, e.g. `/dashboard?tab=1`
     * @param array<string, mixed> $query the request's query parameters
     */
    public function handshakeFor(Auth $auth, string $method, ?string $accept, string $pathWithQuery, array $query): ?BridgeResult
    {
        if (!$auth->needsHandshake) {
            return null;
        }
        // Back from a handshake and still nobody: render signed out. This is
        // the loop guard.
        if (array_key_exists(self::HANDSHAKE_MARKER, $query)) {
            return null;
        }
        $isNavigation = in_array(strtoupper($method), ['GET', 'HEAD'], true)
            && str_contains((string) $accept, 'text/html');
        if (!$isNavigation) {
            return self::error(401, 'session_refresh_required', 'The session cookie expired. Send the SDK token in Authorization, or reload the page.');
        }

        return new BridgeResult(302, headers: [
            'Location' => $this->handshakePath . '?' . http_build_query(['redirect_url' => $pathWithQuery], '', '&', PHP_QUERY_RFC3986),
            'Cache-Control' => 'no-store',
        ]);
    }

    /**
     * The handshake page: refreshes the session in the browser, posts it to
     * the bridge, and returns to where the person was going.
     *
     * Serve it at `handshakePath` with `Content-Type: text/html`,
     * `Cache-Control: no-store`. `redirect_url` must be a same-site path;
     * anything else returns to `/`, so this can never become an open
     * redirect.
     */
    public static function handshakeHtml(
        ?string $redirectUrl,
        string $publishableKey,
        string $bridgePath,
        ?string $apiUrl = null,
        ?string $uiScriptUrl = null,
    ): string {
        $requested = $redirectUrl ?? '/';
        // `//evil.example` and `/\evil.example` are absolute to a browser.
        $safe = preg_match('#^/(?![/\\\\])#', $requested) === 1 ? $requested : '/';
        $back = $safe . (str_contains($safe, '?') ? '&' : '?') . self::HANDSHAKE_MARKER . '=1';

        $config = json_encode([
            'publishableKey' => $publishableKey,
            'apiUrl' => $apiUrl,
            'bridge' => $bridgePath,
            'back' => $back,
        ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $script = htmlspecialchars($uiScriptUrl ?? self::DEFAULT_UI_SCRIPT, ENT_QUOTES);

        return <<<HTML
            <!doctype html><meta charset="utf-8"><meta name="robots" content="noindex"><title>Signing in…</title>
            <script src="{$script}"></script>
            <script>
            (async function () {
              var c = {$config};
              try {
                window.ZevAuthUI.init({ publishableKey: c.publishableKey, apiUrl: c.apiUrl || undefined, sessionBridge: { url: c.bridge } });
                var client = window.ZevAuthUI.getClient();
                await client.load();
                await client.syncSessionBridge();
              } catch (e) {}
              location.replace(c.back);
            })();
            </script>
            HTML;
    }

    /**
     * Cookies that end the bridged session (for a server-side sign-out).
     *
     * @return list<Cookie>
     */
    public function clearCookies(): array
    {
        $names = $this->cookieNames();

        return [$this->cookie($names['session'], '', 0), $this->cookie($names['client'], '', 0)];
    }

    private function cookie(string $name, string $value, int $maxAge): Cookie
    {
        return new Cookie($name, $value, $maxAge, $this->secure, $this->cookieDomain);
    }

    /**
     * @param array<string, string> $headers
     */
    private static function error(int $status, string $code, string $message, array $headers = []): BridgeResult
    {
        return new BridgeResult($status, ['error' => ['code' => $code, 'message' => $message]], [], $headers + ['Cache-Control' => 'no-store']);
    }
}
