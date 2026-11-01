<?php

declare(strict_types=1);

namespace ZevAuth\Laravel\Http;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use ZevAuth\Exception\AuthRefusedException;
use ZevAuth\Laravel\ZevAuthService;
use ZevAuth\ZevAuth;

/**
 * The `zevauth` route middleware.
 *
 *     Route::middleware('zevauth')->group(…);                    // signed in
 *     Route::middleware('zevauth:mfa')->post('/payouts', …);       // and two-step verified
 *     Route::middleware('zevauth:allow-pending')->get('/setup', …); // even with tasks left
 *
 * Refusals use the shared envelope: 401 `unauthorized`, 403
 * `session_task_pending`, 403 `mfa_required`. A page whose bridge cookie
 * has lapsed is sent through the handshake first, so the person is not
 * treated as signed out just because their cookie aged out.
 */
final class Authenticate
{
    public function __construct(private readonly ZevAuthService $zevauth)
    {
    }

    public function handle(Request $request, Closure $next, string ...$options): Response
    {
        $auth = $this->zevauth->auth($request);

        $handshake = $this->zevauth->bridge->handshakeFor(
            $auth,
            $request->getMethod(),
            $request->headers->get('Accept'),
            $request->getRequestUri(),
            $request->query->all(),
        );
        if ($handshake !== null) {
            return $handshake->status === 302
                ? new RedirectResponse($handshake->headers['Location'], 302, ['Cache-Control' => 'no-store'])
                : new JsonResponse($handshake->body, $handshake->status);
        }

        try {
            ZevAuth::check(
                $auth,
                allowPendingTasks: in_array('allow-pending', $options, true),
                requireMfa: in_array('mfa', $options, true),
            );
        } catch (AuthRefusedException $e) {
            return new JsonResponse($e->toArray(), $e->status, ['Cache-Control' => 'no-store']);
        }

        return $next($request);
    }
}
