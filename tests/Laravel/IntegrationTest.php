<?php

declare(strict_types=1);

namespace ZevAuth\Tests\Laravel;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\TestCase;
use ZevAuth\Bridge\SessionBridge;
use ZevAuth\Laravel\Facades\ZevAuth;
use ZevAuth\Laravel\ZevAuthServiceProvider;
use ZevAuth\Laravel\ZevAuthUser;
use ZevAuth\Tests\Support\Fixtures;
use ZevAuth\TokenVerifier;

final class IntegrationTest extends TestCase
{
    /** @var array<string, string> */
    private array $tokens = [];

    protected function getPackageProviders($app): array
    {
        return [ZevAuthServiceProvider::class];
    }

    protected function getPackageAliases($app): array
    {
        return ['ZevAuth' => ZevAuth::class];
    }

    protected function defineEnvironment($app): void
    {
        $tokens = Fixtures::load('tokens.json');
        $app['config']->set('zevauth.environment_id', $tokens['environmentId']);
        $app['config']->set('zevauth.publishable_key', 'pk_test_fixture');
        $app['config']->set('zevauth.webhook_secret', Fixtures::load('webhooks.json')['secret']);
        $app['config']->set('auth.guards.zevauth', ['driver' => 'zevauth']);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $fixture = Fixtures::load('tokens.json');
        foreach ($fixture['cases'] as $case) {
            $this->tokens[$case['name']] = $case['token'];
        }

        // The fixtures' keys and fixed clock in place of fetching.
        $clock = Fixtures::clock($fixture['now']);
        $verifier = new TokenVerifier(
            environmentId: $fixture['environmentId'],
            issuer: $fixture['issuer'],
            jwks: Fixtures::load('jwks.json'),
            clock: $clock,
        );
        $this->app->instance(TokenVerifier::class, $verifier);
        $this->app->instance(SessionBridge::class, new SessionBridge($verifier, clock: $clock));
        $this->app->forgetInstance(\ZevAuth\Laravel\ZevAuthService::class);

        Route::get('/me', fn (Request $r) => ['id' => ZevAuth::auth($r)->userId])->middleware('zevauth');
        Route::get('/payouts', fn () => 'ok')->middleware('zevauth:mfa');
        Route::get('/setup', fn () => 'ok')->middleware('zevauth:allow-pending');
        Route::get('/guard', fn () => ['id' => Auth::guard('zevauth')->id(), 'class' => Auth::guard('zevauth')->user() === null ? null : get_class(Auth::guard('zevauth')->user())]);
        Route::get('/page', fn () => Blade::render('@zevauthSignedIn hello {{ $name }} @endzevauthSignedIn @zevauthSignedOut please sign in @endzevauthSignedOut', ['name' => 'Ada']));
        Route::zevauthWebhooks('/webhooks/zevauth', fn (Request $r) => ['type' => $r->attributes->get('zevauth.event')['type']]);
    }

    public function testMiddlewareRefusesWithTheSharedEnvelope(): void
    {
        $this->getJson('/me')->assertStatus(401)->assertJsonPath('error.code', 'unauthorized');
        $this->getJson('/me', ['Authorization' => 'Bearer ' . $this->tokens['expired']])->assertStatus(401);

        $this->getJson('/me', ['Authorization' => 'Bearer ' . $this->tokens['valid']])
            ->assertOk()->assertJsonPath('id', 'user_fixture_1');

        $this->getJson('/me', ['Authorization' => 'Bearer ' . $this->tokens['valid_pending_task']])
            ->assertStatus(403)
            ->assertJsonPath('error.code', 'session_task_pending')
            ->assertJsonPath('error.pendingTasks', ['setup_mfa']);
        $this->get('/setup', ['Authorization' => 'Bearer ' . $this->tokens['valid_pending_task']])->assertOk();

        $this->getJson('/payouts', ['Authorization' => 'Bearer ' . $this->tokens['valid']])
            ->assertStatus(403)->assertJsonPath('error.code', 'mfa_required');
        $this->get('/payouts', ['Authorization' => 'Bearer ' . $this->tokens['valid_mfa']])->assertOk();
    }

    public function testGuardMakesAuthUserWork(): void
    {
        $this->getJson('/guard', ['Authorization' => 'Bearer ' . $this->tokens['valid_with_organization']])
            ->assertJson(['id' => 'user_fixture_1', 'class' => ZevAuthUser::class]);
        $this->getJson('/guard')->assertJson(['id' => null, 'class' => null]);
    }

    public function testBladeDirectives(): void
    {
        $this->get('/page', ['Authorization' => 'Bearer ' . $this->tokens['valid']])->assertSee('hello Ada')->assertDontSee('please sign in');
        $this->get('/page')->assertSee('please sign in')->assertDontSee('hello');
    }

    public function testBridgeRoutesSetCookiesThatPagesThenRead(): void
    {
        $response = $this->call('POST', '/zevauth/session', [], [], [], [
            'HTTP_X_ZEVAUTH_BRIDGE' => '1',
            'HTTP_ORIGIN' => 'http://localhost',
            'CONTENT_TYPE' => 'application/json',
        ], json_encode(['token' => $this->tokens['valid']]));
        $response->assertNoContent();
        $cookie = $response->headers->getCookies()[0];
        $this->assertSame('__Host-zevauth_session', $cookie->getName());
        $this->assertSame($this->tokens['valid'], $cookie->getValue());
        $this->assertTrue($cookie->isHttpOnly());
        $this->assertTrue($cookie->isSecure());

        $this->call('POST', '/zevauth/session', [], [], [], ['HTTP_ORIGIN' => 'http://localhost'], json_encode(['token' => $this->tokens['valid']]))
            ->assertStatus(403)->assertJsonPath('error.code', 'bridge_header_missing');
        $this->call('POST', '/zevauth/session', [], [], [], ['HTTP_X_ZEVAUTH_BRIDGE' => '1', 'HTTP_ORIGIN' => 'https://evil.example'], json_encode(['token' => $this->tokens['valid']]))
            ->assertStatus(403)->assertJsonPath('error.code', 'bridge_origin_not_allowed');

        $this->call('GET', '/me', [], ['__Host-zevauth_session' => $this->tokens['valid']], [], ['HTTP_ACCEPT' => 'application/json'])
            ->assertOk()->assertJsonPath('id', 'user_fixture_1');
    }

    public function testLapsedCookieSendsPagesThroughTheHandshake(): void
    {
        $this->call('GET', '/me', [], ['__Host-zevauth_client' => '1'], [], ['HTTP_ACCEPT' => 'text/html'])
            ->assertRedirect('/zevauth/handshake?redirect_url=%2Fme');
        $this->call('GET', '/me?__zevauth_handshake=1', [], ['__Host-zevauth_client' => '1'], [], ['HTTP_ACCEPT' => 'text/html'])
            ->assertStatus(401);

        $this->get('/zevauth/handshake?redirect_url=%2Fme')
            ->assertOk()
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertSee('pk_test_fixture', false)
            ->assertSee('syncSessionBridge', false);
    }

    public function testWebhookRouteVerifiesTheRawBody(): void
    {
        $fixture = Fixtures::load('webhooks.json');
        $case = $fixture['cases'][0];
        // Sign for "now", since the middleware uses the real clock.
        $t = time();
        $signature = "t={$t},v1=" . hash_hmac('sha256', "{$t}.{$case['payload']}", $fixture['secret']);

        $this->call('POST', '/webhooks/zevauth', [], [], [], ['HTTP_ZEVAUTH_SIGNATURE' => $signature, 'CONTENT_TYPE' => 'application/json'], $case['payload'])
            ->assertOk()->assertJsonPath('type', 'user.created');
        $this->call('POST', '/webhooks/zevauth', [], [], [], ['HTTP_ZEVAUTH_SIGNATURE' => $case['signature'], 'CONTENT_TYPE' => 'application/json'], $case['payload'])
            ->assertStatus(400)->assertJsonPath('error.code', 'webhook_timestamp_out_of_range');
    }
}
