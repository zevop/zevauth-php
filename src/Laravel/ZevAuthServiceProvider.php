<?php

declare(strict_types=1);

namespace ZevAuth\Laravel;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Foundation\CachesRoutes;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use ZevAuth\Bridge\SessionBridge;
use ZevAuth\Laravel\Http\Authenticate;
use ZevAuth\Laravel\Http\BridgeController;
use ZevAuth\Laravel\Http\VerifyWebhook;
use ZevAuth\TokenVerifier;
use ZevAuth\ZevAuthClient;

/**
 * Laravel integration, discovered automatically.
 *
 * Adds: the `zevauth` and `zevauth.webhook` middleware, a `zevauth` guard
 * driver, the `@zevauthSignedIn` / `@zevauthSignedOut` Blade directives,
 * the session-bridge routes, a `Route::zevauthWebhooks()` helper, and the
 * `ZevAuth` facade.
 */
final class ZevAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../../config/zevauth.php', 'zevauth');

        $this->app->singleton(TokenVerifier::class, static function (Application $app): TokenVerifier {
            $config = $app->make('config');
            $store = $config->get('zevauth.cache_store');

            return new TokenVerifier(
                environmentId: (string) $config->get('zevauth.environment_id'),
                apiUrl: (string) $config->get('zevauth.api_url', TokenVerifier::DEFAULT_API_URL),
                clockSkewSeconds: (int) $config->get('zevauth.clock_skew_seconds', 5),
                // Laravel's cache repository is a PSR-16 cache: keys and the
                // refetch cooldown survive across PHP-FPM requests.
                cache: $app->make('cache')->store($store ?: null),
            );
        });

        $this->app->singleton(SessionBridge::class, static function (Application $app): SessionBridge {
            $config = $app->make('config');
            $origins = array_values(array_filter((array) $config->get('zevauth.bridge.allowed_origins', []), 'is_string'));

            return new SessionBridge(
                $app->make(TokenVerifier::class),
                allowedOrigins: $origins === [] ? null : $origins,
                cookieDomain: $config->get('zevauth.bridge.cookie_domain') ?: null,
                secure: (bool) $config->get('zevauth.bridge.secure', true),
                handshakePath: (string) $config->get('zevauth.bridge.handshake_path', SessionBridge::DEFAULT_HANDSHAKE_PATH),
            );
        });

        $this->app->singleton(ZevAuthService::class, static fn (Application $app) => new ZevAuthService(
            $app,
            $app->make(TokenVerifier::class),
            $app->make(SessionBridge::class),
        ));

        $this->app->singleton(ZevAuthClient::class, static function (Application $app): ZevAuthClient {
            $config = $app->make('config');

            return new ZevAuthClient(
                (string) $config->get('zevauth.secret_key'),
                apiUrl: (string) $config->get('zevauth.api_url', TokenVerifier::DEFAULT_API_URL),
            );
        });
    }

    public function boot(): void
    {
        $this->publishes([__DIR__ . '/../../config/zevauth.php' => config_path('zevauth.php')], 'zevauth-config');

        /** @var Router $router */
        $router = $this->app->make('router');
        $router->aliasMiddleware('zevauth', Authenticate::class);
        $router->aliasMiddleware('zevauth.webhook', VerifyWebhook::class);

        Auth::extend('zevauth', static fn (Application $app) => new ZevAuthGuard(
            $app->make(ZevAuthService::class),
            static fn () => $app->make('request'),
        ));

        Blade::if('zevauthSignedIn', fn () => $this->app->make(ZevAuthService::class)->auth()->isSignedIn);
        Blade::if('zevauthSignedOut', fn () => !$this->app->make(ZevAuthService::class)->auth()->isSignedIn);

        // The bridge cookies are set by these routes unencrypted, and read
        // raw. Without this, the web group's EncryptCookies would try to
        // decrypt them and hand the app nothing.
        EncryptCookies::except(array_values($this->app->make(SessionBridge::class)->cookieNames()));

        Route::macro('zevauthWebhooks', function (string $uri, mixed $action): RoutingRoute {
            $route = Route::post($uri, $action)->middleware('zevauth.webhook');
            // Deliveries come from ZevAuth's servers, not a browser form.
            foreach (['Illuminate\Foundation\Http\Middleware\ValidateCsrfToken', 'Illuminate\Foundation\Http\Middleware\VerifyCsrfToken'] as $csrf) {
                if (class_exists($csrf)) {
                    $route->withoutMiddleware($csrf);
                }
            }

            return $route;
        });

        $routesCached = $this->app instanceof CachesRoutes && $this->app->routesAreCached();
        if ((bool) $this->app->make('config')->get('zevauth.bridge.enabled', true) && !$routesCached) {
            $config = $this->app->make('config');
            Route::post((string) $config->get('zevauth.bridge.path', '/zevauth/session'), [BridgeController::class, 'session'])
                ->name('zevauth.bridge');
            Route::get((string) $config->get('zevauth.bridge.handshake_path', SessionBridge::DEFAULT_HANDSHAKE_PATH), [BridgeController::class, 'handshake'])
                ->name('zevauth.handshake');
        }
    }
}
