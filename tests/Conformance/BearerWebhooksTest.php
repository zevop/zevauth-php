<?php

declare(strict_types=1);

namespace ZevAuth\Tests\Conformance;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ZevAuth\Bearer;
use ZevAuth\Exception\WebhookException;
use ZevAuth\Tests\Support\Fixtures;
use ZevAuth\Webhooks\Webhook;

/** bearer.json and webhooks.json. */
final class BearerWebhooksTest extends TestCase
{
    /** @return iterable<string, array{array<string, mixed>}> */
    public static function bearerCases(): iterable
    {
        foreach (Fixtures::load('bearer.json')['cases'] as $i => $case) {
            yield 'bearer #' . $i . ' ' . ($case['note'] ?? substr((string) $case['header'], 0, 16)) => [$case];
        }
    }

    /** @param array<string, mixed> $case */
    #[DataProvider('bearerCases')]
    public function testBearerExtraction(array $case): void
    {
        $this->assertSame($case['token'], Bearer::fromHeader($case['header']));
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function webhookCases(): iterable
    {
        foreach (Fixtures::load('webhooks.json')['cases'] as $case) {
            yield $case['name'] => [$case];
        }
    }

    /** @param array<string, mixed> $case */
    #[DataProvider('webhookCases')]
    public function testWebhookVerification(array $case): void
    {
        $fixture = Fixtures::load('webhooks.json');
        try {
            Webhook::verify($case['payload'], $case['signature'], $case['secret'] ?? $fixture['secret'], $fixture['toleranceSeconds'], $fixture['now']);
            $this->assertTrue($case['valid'], "{$case['name']} should have been refused");
        } catch (WebhookException $e) {
            $this->assertFalse($case['valid'], "{$case['name']} refused with {$e->errorCode}");
            $this->assertSame($case['error'], $e->errorCode);
        }
    }

    public function testConstructEventReturnsTheParsedEvent(): void
    {
        $fixture = Fixtures::load('webhooks.json');
        $case = $fixture['cases'][0];
        $event = Webhook::constructEvent($case['payload'], $case['signature'], $fixture['secret'], now: $fixture['now']);

        $this->assertSame('user.created', $event['type']);
        $this->assertSame('evt_fixture_1', $event['id']);
    }
}
