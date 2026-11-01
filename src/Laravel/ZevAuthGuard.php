<?php

declare(strict_types=1);

namespace ZevAuth\Laravel;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;

/**
 * A guard that reads the ZevAuth session, so `Auth::user()`,
 * `$request->user()`, `@auth` and the `auth` middleware all work.
 *
 * In config/auth.php:
 *
 *     'guards' => ['web' => ['driver' => 'zevauth']],
 *
 * Signing in and out happen in the browser SDK, so `attempt()`,
 * `login()` and friends do not exist here; `validate()` is always false.
 *
 * ── Why it reads the request every time ───────────────────────────
 * Laravel keeps guard instances for the life of the application. Under
 * Octane, and in tests, that outlives a request, so a guard that kept
 * its first answer would hand one person's session to the next request.
 * The answer is cached on each request instead (`ZevAuthService::auth`).
 */
final class ZevAuthGuard implements Guard
{
    /** Set only by `setUser()`, for the current request. */
    private ?Authenticatable $user = null;
    private ?Request $userFor = null;

    /**
     * @param Closure(): Request $currentRequest
     */
    public function __construct(
        private readonly ZevAuthService $zevauth,
        private Closure $currentRequest,
    ) {
    }

    public function check(): bool
    {
        return $this->user() !== null;
    }

    public function guest(): bool
    {
        return !$this->check();
    }

    public function user(): ?Authenticatable
    {
        $request = ($this->currentRequest)();
        if ($this->user !== null && $this->userFor === $request) {
            return $this->user;
        }
        $auth = $this->zevauth->auth($request);

        return $auth->isSignedIn ? new ZevAuthUser($auth) : null;
    }

    public function id(): ?string
    {
        $user = $this->user();

        return $user === null ? null : (string) $user->getAuthIdentifier();
    }

    /** @param array<string, mixed> $credentials */
    public function validate(array $credentials = []): bool
    {
        return false;
    }

    public function hasUser(): bool
    {
        return $this->user() !== null;
    }

    public function setUser(Authenticatable $user): static
    {
        $this->user = $user;
        $this->userFor = ($this->currentRequest)();

        return $this;
    }

    public function setRequest(Request $request): static
    {
        $this->currentRequest = static fn (): Request => $request;
        $this->user = null;

        return $this;
    }
}
