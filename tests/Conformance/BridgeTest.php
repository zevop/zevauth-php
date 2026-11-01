<?php

declare(strict_types=1);

namespace ZevAuth\Tests\Conformance;

use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ZevAuth\Bridge\SessionBridge;
use ZevAuth\Tests\Support\Fixtures;
use ZevAuth\TokenVerifier;
use ZevAuth\ZevAuth;

/** bridge.json, plus the cookie reading and handshake rules. */
final class BridgeTest extends TestCase
{
    /** @return iterable<string, array{array<string, mixed>}> */
    public static function cases(): iterable
    {
        foreach (Fixtures::load('bridge.json')['cases'] as $case) {
            yield $case['name'] => [$case];
        }
    }

    /** @param array<string, mixed> $case */
    #[DataProvider('cases')]
    public function testBridgeEndpoint(array $case): void
    {
        $fixture = Fixtures::load('bridge.json');
        $request = $case['request'];
        $result = $this->bridge()->handle(
            $request['method'],
            $request['bridgeHeader'] ? $fixture['header']['value'] : null,
            $request['origin'] ?? null,
            $fixture['appOrigin'],
            json_encode($request['body'] ?? new \stdClass()),
        );

        $this->assertSame($case['expect']['status'], $result->status, $case['name']);
        if (isset($case['expect']['code'])) {
            $this->assertSame($case['expect']['code'], $result->errorCode());
        }

        $byName = [];
        foreach ($result->cookies as $cookie) {
            $byName[$cookie->name] = $cookie;
        }
        switch ($case['expect']['cookie']) {
            case 'set':
                $session = $byName['__Host-zevauth_session'];
                $this->assertSame($request['body']['token'], $session->value);
                $this->assertSame($case['expect']['maxAgeSeconds'], $session->maxAge);
                $this->assertSame('1', $byName['__Host-zevauth_client']->value);
                $this->assertStringContainsString('HttpOnly', $session->toHeader());
                $this->assertStringContainsString('Secure', $session->toHeader());
                $this->assertStringContainsString('SameSite=Lax', $session->toHeader());
                break;
            case 'cleared':
                $this->assertSame(0, $byName['__Host-zevauth_session']->maxAge);
                $this->assertSame(0, $byName['__Host-zevauth_client']->maxAge);
                break;
            case 'unchanged':
                $this->assertSame([], $result->cookies);
                break;
        }
    }

    public function testCookieNamesFollowConfiguration(): void
    {
        $verifier = $this->verifier();
        $this->assertSame(['session' => '__Host-zevauth_session', 'client' => '__Host-zevauth_client'], (new SessionBridge($verifier))->cookieNames());
        $this->assertSame(['session' => '__Secure-zevauth_session', 'client' => '__Secure-zevauth_client'], (new SessionBridge($verifier, cookieDomain: '.example.com'))->cookieNames());
        $this->assertSame(['session' => 'zevauth_session', 'client' => 'zevauth_client'], (new SessionBridge($verifier, secure: false))->cookieNames());
    }

    public function testReadsTheCookieAndKnowsWhenToHandshake(): void
    {
        $tokens = $this->tokens();
        $bridge = $this->bridge();

        $fromCookie = $bridge->readAuth(null, ['__Host-zevauth_session' => $tokens['valid']]);
        $this->assertTrue($fromCookie->isSignedIn);
        $this->assertSame('user_fixture_1', $fromCookie->userId);

        $expired = $bridge->readAuth(null, ['__Host-zevauth_session' => $tokens['expired']]);
        $this->assertFalse($expired->isSignedIn);
        $this->assertTrue($expired->needsHandshake);

        $gone = $bridge->readAuth(null, ['__Host-zevauth_client' => '1']);
        $this->assertTrue($gone->needsHandshake, 'session cookie gone, client cookie left: offer a handshake');

        $never = $bridge->readAuth(null, []);
        $this->assertFalse($never->needsHandshake, 'nobody ever signed in: no handshake');

        $header = $bridge->readAuth('Bearer ' . $tokens['expired'], ['__Host-zevauth_client' => '1']);
        $this->assertFalse($header->needsHandshake, 'API calls with a header never handshake');
    }

    public function testHandshakeRedirectsPagesRefusesApiCallsAndStopsLoops(): void
    {
        $bridge = $this->bridge();
        $lapsed = $bridge->readAuth(null, ['__Host-zevauth_client' => '1']);

        $page = $bridge->handshakeFor($lapsed, 'GET', 'text/html,application/xhtml+xml', '/dashboard?tab=1', ['tab' => '1']);
        $this->assertSame(302, $page?->status);
        $this->assertSame('/zevauth/handshake?redirect_url=%2Fdashboard%3Ftab%3D1', $page?->headers['Location']);

        $api = $bridge->handshakeFor($lapsed, 'POST', 'application/json', '/api/items', []);
        $this->assertSame(401, $api?->status);
        $this->assertSame('session_refresh_required', $api?->errorCode());

        $back = $bridge->handshakeFor($lapsed, 'GET', 'text/html', '/dashboard?__zevauth_handshake=1', [SessionBridge::HANDSHAKE_MARKER => '1']);
        $this->assertNull($back, 'loop guard: back from a handshake renders signed out');
    }

    public function testHandshakePageNeverRedirectsOffSite(): void
    {
        foreach (['/dashboard?x=1' => '/dashboard?x=1&__zevauth_handshake=1', '//evil.example' => '/?__zevauth_handshake=1', '/\\evil.example' => '/?__zevauth_handshake=1', 'https://evil.example' => '/?__zevauth_handshake=1'] as $requested => $back) {
            $html = SessionBridge::handshakeHtml($requested, 'pk_test_fixture', '/zevauth/session');
            $this->assertStringContainsString('"back":"' . str_replace('&', '\\' . 'u0026', $back) . '"', $html, $requested);
        }
        $this->assertStringNotContainsString('</script><script>', SessionBridge::handshakeHtml('/x</script><script>alert(1)', 'pk', '/b'));
    }

    public function testPsr7AdaptersRenderTheSameDecisions(): void
    {
        $fixture = Fixtures::load('bridge.json');
        $set = $fixture['cases'][0];
        $zevauth = new ZevAuth($this->verifier(), $this->bridge(), 'pk_test_fixture', responseFactory: new HttpFactory(), streamFactory: new HttpFactory());

        $request = (new ServerRequest('POST', $fixture['appOrigin'] . '/zevauth/session', [
            'x-zevauth-bridge' => '1',
            'Origin' => $fixture['appOrigin'],
            'Content-Type' => 'application/json',
        ], json_encode($set['request']['body'])));
        $response = $zevauth->handleSessionBridge($request);
        $this->assertSame(204, $response->getStatusCode());
        $this->assertCount(2, $response->getHeader('Set-Cookie'));

        $page = (new ServerRequest('GET', $fixture['appOrigin'] . '/zevauth/handshake?redirect_url=%2Fdashboard'))
            ->withQueryParams(['redirect_url' => '/dashboard']);
        $html = $zevauth->handshakePage($page);
        $this->assertSame('no-store', $html->getHeaderLine('Cache-Control'));
        $this->assertStringContainsString('pk_test_fixture', (string) $html->getBody());

        $nav = (new ServerRequest('GET', $fixture['appOrigin'] . '/dashboard', ['Accept' => 'text/html']))
            ->withCookieParams(['__Host-zevauth_client' => '1']);
        $result = $zevauth->authenticateRequest($nav);
        $this->assertFalse($result['auth']->isSignedIn);
        $this->assertSame(302, $result['handshake']?->getStatusCode());
    }

    private function bridge(): SessionBridge
    {
        return new SessionBridge($this->verifier(), clock: Fixtures::clock(Fixtures::load('bridge.json')['now']));
    }

    private function verifier(): TokenVerifier
    {
        $tokens = Fixtures::load('tokens.json');

        return new TokenVerifier(
            environmentId: $tokens['environmentId'],
            issuer: $tokens['issuer'],
            jwks: Fixtures::load('jwks.json'),
            clock: Fixtures::clock($tokens['now']),
        );
    }

    /** @return array<string, string> */
    private function tokens(): array
    {
        $out = [];
        foreach (Fixtures::load('tokens.json')['cases'] as $case) {
            $out[$case['name']] = $case['token'];
        }

        return $out;
    }
}
