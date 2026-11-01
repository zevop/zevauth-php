# ZevAuth for PHP

Verify ZevAuth sessions, call the ZevAuth backend API and check webhook
signatures from Laravel, Symfony, Slim, WordPress or plain PHP.

```sh
composer require zevauth/zevauth-php
```

PHP 8.1 or later. You'll also want a PSR-18 HTTP client; Guzzle is the
usual choice (`composer require guzzlehttp/guzzle`).

## Who is signed in

```php
use ZevAuth\ZevAuth;

$zevauth = ZevAuth::create(environmentId: 'env_live_…', publishableKey: 'pk_live_…');

$auth = $zevauth->getAuthFromGlobals();   // plain PHP and WordPress
$auth = $zevauth->getAuth($request);      // any PSR-7 request

if ($auth->isSignedIn) {
    echo $auth->userId;                   // user_…
    $auth->has(permission: 'org:members:manage');
}
```

`getAuth()` never throws. A missing, expired or invalid token means nobody
is signed in. To refuse instead, call `requireAuth()`: it throws
`AuthRefusedException`, whose `toArray()` is the response body to send.

| Status | Code | When |
| --- | --- | --- |
| 401 | `unauthorized` | Not signed in |
| 403 | `session_task_pending` | The person must finish a task first, such as setting up two-step verification |
| 403 | `mfa_required` | You passed `requireMfa: true` and they haven't verified a second factor |

Under PHP-FPM, pass a shared PSR-16 cache (`cache:` APCu, Redis…) so the
signing keys are fetched every ten minutes rather than on every request.

## Server-rendered pages

Browsers asking for a page send no `Authorization` header. Turn on the
session bridge in the browser SDK (`sessionBridge: { url: '/zevauth/session' }`)
and mount two routes. The browser then keeps a short-lived, HttpOnly cookie
up to date, and `getAuth()` reads it.

```php
$zevauth->handleSessionBridge($request);   // POST /zevauth/session
$zevauth->handshakePage($request);         // GET  /zevauth/handshake

['auth' => $auth, 'handshake' => $redirect] = $zevauth->authenticateRequest($request);
if ($redirect) return $redirect;           // the cookie lapsed: refresh in the browser and come back
```

The refresh token never leaves the browser, and the server never refreshes.
<https://docs.zevauth.com/concepts/session-bridge> explains why.

## Laravel

Laravel 11 or later. The integration is discovered automatically.

```sh
php artisan vendor:publish --tag=zevauth-config
```

```php
Route::middleware('zevauth')->get('/dashboard', …);        // signed in
Route::middleware('zevauth:mfa')->post('/payouts', …);      // and two-step verified
Route::zevauthWebhooks('/webhooks/zevauth', HandleEvent::class);

ZevAuth::auth()->userId;
ZevAuth::client()->users->get($id);
```

In Blade:

```blade
@zevauthSignedIn Welcome back @endzevauthSignedIn
@zevauthSignedOut <div id="sign-in"></div> @endzevauthSignedOut
```

Set a guard's driver to `zevauth` in `config/auth.php` and `Auth::user()`
and `$request->user()` return the signed-in person, with no database query.

## Backend API

```php
use ZevAuth\ZevAuthClient;

$client = new ZevAuthClient(getenv('ZEVAUTH_SECRET_KEY'));
$user = $client->users->get('user_…');
foreach ($client->users->iterate(query: 'ada') as $user) { … }
$client->organizations->addMember('org_…', userId: 'user_…', role: 'org:admin');
```

Errors are `ApiException`s with `errorCode`, `status` and `requestId`.
Rate limits and gateway errors are retried. A 500 never is, because the
request may already have run.

## Webhooks

```php
use ZevAuth\Webhooks\Webhook;

$event = Webhook::constructEvent(
    payload: file_get_contents('php://input'),     // the raw body
    signature: $_SERVER['HTTP_ZEVAUTH_SIGNATURE'] ?? '',
    secret: getenv('ZEVAUTH_WEBHOOK_SECRET'),
);
```

## The same everywhere

Every ZevAuth server library implements one contract and passes the same
conformance tests, so behaviour here matches the libraries for Node,
Python, Ruby, Go and Java. The contract lives at
<https://github.com/zevop/zevauth-sdk/tree/main/spec>. Its fixtures are copied
into `tests/fixtures`; `composer sync-fixtures` refreshes them.

```sh
composer test      # PHPUnit: conformance and Laravel suites
composer analyse   # PHPStan
```

## Documentation

- PHP: <https://docs.zevauth.com/sdk/php>
- Laravel: <https://docs.zevauth.com/sdk/laravel>

## Support

Questions and bug reports: open an issue here, or contact ZevAuth support.

## License

[MIT](LICENSE). Copyright (c) 2026 Zevop Inc.
