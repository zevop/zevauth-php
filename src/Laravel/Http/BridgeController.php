<?php

declare(strict_types=1);

namespace ZevAuth\Laravel\Http;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Symfony\Component\HttpFoundation\Cookie as SymfonyCookie;
use ZevAuth\Bridge\BridgeResult;
use ZevAuth\Bridge\Cookie;
use ZevAuth\Bridge\SessionBridge;
use ZevAuth\Exception\ConfigurationException;
use ZevAuth\TokenVerifier;

/**
 * The session bridge endpoint and the handshake page.
 *
 * Registered outside the `web` middleware group on purpose: the browser
 * SDK posts here with its own CSRF protection (a custom header plus an
 * origin check), and these cookies must not be encrypted, so Laravel's
 * session, CSRF and cookie-encryption middleware stay out of the way.
 */
final class BridgeController
{
    public function __construct(
        private readonly SessionBridge $bridge,
        private readonly TokenVerifier $verifier,
        private readonly Repository $config,
    ) {
    }

    public function session(Request $request): Response|JsonResponse
    {
        return self::respond($this->bridge->handle(
            $request->getMethod(),
            $request->headers->get(SessionBridge::HEADER),
            $request->headers->get('Origin'),
            $request->getSchemeAndHttpHost(),
            (string) $request->getContent(),
        ));
    }

    public function handshake(Request $request): Response
    {
        $publishableKey = (string) $this->config->get('zevauth.publishable_key');
        if ($publishableKey === '') {
            throw new ConfigurationException('Set ZEVAUTH_PUBLISHABLE_KEY to serve the handshake page.', 'missing_publishable_key');
        }
        $redirect = $request->query('redirect_url');
        $html = SessionBridge::handshakeHtml(
            is_string($redirect) ? $redirect : null,
            $publishableKey,
            (string) $this->config->get('zevauth.bridge.path', '/zevauth/session'),
            $this->verifier->apiUrl === TokenVerifier::DEFAULT_API_URL ? null : $this->verifier->apiUrl,
            $this->config->get('zevauth.bridge.ui_script_url') ?: null,
        );

        return new Response($html, 200, [
            'Content-Type' => 'text/html; charset=utf-8',
            'Cache-Control' => 'no-store',
            'Referrer-Policy' => 'same-origin',
        ]);
    }

    public static function respond(BridgeResult $result): Response|JsonResponse
    {
        $response = $result->body === null
            ? new Response('', $result->status, $result->headers)
            : new JsonResponse($result->body, $result->status, $result->headers);
        foreach ($result->cookies as $cookie) {
            $response->headers->setCookie(self::toSymfony($cookie));
        }

        return $response;
    }

    public static function toSymfony(Cookie $cookie): SymfonyCookie
    {
        return SymfonyCookie::create(
            $cookie->name,
            $cookie->value === '' ? null : $cookie->value,
            $cookie->maxAge > 0 ? time() + $cookie->maxAge : 1,
            $cookie->path,
            $cookie->domain,
            $cookie->secure,
            $cookie->httpOnly,
            true,
            match (strtolower($cookie->sameSite)) {
                'strict' => SymfonyCookie::SAMESITE_STRICT,
                'none' => SymfonyCookie::SAMESITE_NONE,
                default => SymfonyCookie::SAMESITE_LAX,
            },
        );
    }
}
