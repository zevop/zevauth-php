<?php

declare(strict_types=1);

return [

    /*
    | Your environment, from the ZevAuth console under API keys. The
    | environment id is what tokens are checked against: a test token is
    | refused on a live environment and the other way round.
    */
    'environment_id' => env('ZEVAUTH_ENVIRONMENT_ID'),
    'publishable_key' => env('ZEVAUTH_PUBLISHABLE_KEY'),

    /* Server-side only. Needed for the backend API client. */
    'secret_key' => env('ZEVAUTH_SECRET_KEY'),

    'api_url' => env('ZEVAUTH_API_URL', 'https://api.zevauth.net'),

    /*
    | Where the signing keys are cached between requests: a cache store name
    | from config/cache.php, or null for the default store. Under PHP-FPM a
    | shared store means the keys are fetched once every ten minutes, not on
    | every request.
    */
    'cache_store' => env('ZEVAUTH_CACHE_STORE'),

    'clock_skew_seconds' => 5,

    /* The signing secret of your webhook endpoint (whsec_…). */
    'webhook_secret' => env('ZEVAUTH_WEBHOOK_SECRET'),

    /*
    | Session bridge: lets server-rendered pages know who is signed in. Turn
    | on `sessionBridge: { url: '/zevauth/session' }` in the browser SDK, and
    | these routes keep the session in an HttpOnly cookie for Blade pages,
    | middleware and Auth::user().
    */
    'bridge' => [
        'enabled' => env('ZEVAUTH_BRIDGE', true),
        'path' => '/zevauth/session',
        'handshake_path' => '/zevauth/handshake',

        // Origins allowed to post sessions. Empty: this app's own origin.
        'allowed_origins' => array_filter(explode(',', (string) env('ZEVAUTH_BRIDGE_ALLOWED_ORIGINS', ''))),

        // Share the session with subdomains, e.g. ".example.com".
        'cookie_domain' => env('ZEVAUTH_COOKIE_DOMAIN'),

        // False only for plain-http local development.
        'secure' => env('ZEVAUTH_SECURE_COOKIES', true),

        // Serve your own copy of @zevauth/ui under a strict CSP.
        'ui_script_url' => env('ZEVAUTH_UI_SCRIPT_URL'),
    ],

];
