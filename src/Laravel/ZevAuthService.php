<?php

declare(strict_types=1);

namespace ZevAuth\Laravel;

use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use ZevAuth\Auth;
use ZevAuth\Bridge\SessionBridge;
use ZevAuth\TokenVerifier;
use ZevAuth\ZevAuth;
use ZevAuth\ZevAuthClient;

/**
 * What the `ZevAuth` facade talks to.
 *
 *     ZevAuth::auth()->userId;              // who made this request
 *     ZevAuth::requireAuth(requireMfa: true);
 *     ZevAuth::client()->users->get($id);   // backend API, secret key
 */
final class ZevAuthService
{
    private const ATTRIBUTE = 'zevauth.auth';

    public function __construct(
        private readonly Container $app,
        public readonly TokenVerifier $verifier,
        public readonly SessionBridge $bridge,
    ) {
    }

    /** Who made the request (the current one by default). Never throws. */
    public function auth(?Request $request = null): Auth
    {
        $request ??= $this->app->make('request');
        $cached = $request->attributes->get(self::ATTRIBUTE);
        if ($cached instanceof Auth) {
            return $cached;
        }

        $cookies = [];
        foreach ($request->cookies->all() as $name => $value) {
            if (is_string($value)) {
                $cookies[(string) $name] = $value;
            }
        }
        $auth = $this->bridge->readAuth($request->headers->get('Authorization'), $cookies);
        $request->attributes->set(self::ATTRIBUTE, $auth);

        return $auth;
    }

    /**
     * @throws \ZevAuth\Exception\AuthRefusedException
     */
    public function requireAuth(bool $allowPendingTasks = false, bool $requireMfa = false, ?Request $request = null): Auth
    {
        return ZevAuth::check($this->auth($request), $allowPendingTasks, $requireMfa);
    }

    /** @return array<string, mixed> */
    public function verifyToken(string $token): array
    {
        return $this->verifier->verify($token);
    }

    /** The backend API client, built from `zevauth.secret_key`. */
    public function client(): ZevAuthClient
    {
        return $this->app->make(ZevAuthClient::class);
    }
}
