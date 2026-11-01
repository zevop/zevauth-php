<?php

declare(strict_types=1);

namespace ZevAuth\Laravel\Facades;

use Illuminate\Support\Facades\Facade;
use ZevAuth\Laravel\ZevAuthService;

/**
 * @method static \ZevAuth\Auth auth(?\Illuminate\Http\Request $request = null)
 * @method static \ZevAuth\Auth requireAuth(bool $allowPendingTasks = false, bool $requireMfa = false, ?\Illuminate\Http\Request $request = null)
 * @method static array<string, mixed> verifyToken(string $token)
 * @method static \ZevAuth\ZevAuthClient client()
 *
 * @see ZevAuthService
 */
final class ZevAuth extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return ZevAuthService::class;
    }
}
