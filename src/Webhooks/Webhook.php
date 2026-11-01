<?php

declare(strict_types=1);

namespace ZevAuth\Webhooks;

use ZevAuth\Exception\WebhookException;

/**
 * Checks that a webhook delivery came from ZevAuth.
 *
 *     $event = Webhook::constructEvent(
 *         payload: file_get_contents('php://input'),
 *         signature: $_SERVER['HTTP_ZEVAUTH_SIGNATURE'] ?? '',
 *         secret: getenv('ZEVAUTH_WEBHOOK_SECRET'),
 *     );
 *
 * **Pass the raw body.** The signature covers the exact bytes received.
 * A body decoded and re-encoded (Laravel's `$request->all()`, a framework
 * that parses JSON for you) fails verification, correctly.
 *
 * Deliveries are at least once: use the `zevauth-delivery-id` header or
 * the event `id` to handle each one once.
 */
final class Webhook
{
    public const SIGNATURE_HEADER = 'zevauth-signature';
    public const DEFAULT_TOLERANCE_SECONDS = 300;

    /**
     * @param string $payload the raw request body
     * @param string $signature the `zevauth-signature` header, `t=…,v1=…`
     * @param string $secret the endpoint's secret, including its `whsec_` prefix
     * @param int|null $now unix seconds, for tests; defaults to the current time
     *
     * @throws WebhookException `webhook_malformed_signature`, `webhook_timestamp_out_of_range` or `webhook_signature_mismatch`
     */
    public static function verify(
        string $payload,
        string $signature,
        string $secret,
        int $toleranceSeconds = self::DEFAULT_TOLERANCE_SECONDS,
        ?int $now = null,
    ): void {
        $timestamp = null;
        $v1 = null;
        foreach (explode(',', $signature) as $part) {
            $at = strpos($part, '=');
            if ($at === false) {
                continue;
            }
            $name = trim(substr($part, 0, $at));
            $value = trim(substr($part, $at + 1));
            if ($name === 't') {
                $timestamp = $value;
            } elseif ($name === 'v1') {
                $v1 = $value;
            }
        }
        if ($timestamp === null || $v1 === null || $v1 === '' || preg_match('/^\d+$/', $timestamp) !== 1) {
            throw new WebhookException('The zevauth-signature header is missing or malformed.', 'webhook_malformed_signature');
        }

        // Rejects replays and futures alike.
        $now ??= time();
        if (abs($now - (int) $timestamp) > $toleranceSeconds) {
            throw new WebhookException('The webhook timestamp is outside the allowed window.', 'webhook_timestamp_out_of_range');
        }

        $expected = hash_hmac('sha256', "{$timestamp}.{$payload}", $secret);
        // Constant time, and exact: the signature is lowercase hex.
        if (!hash_equals($expected, $v1)) {
            throw new WebhookException('The webhook signature does not match.', 'webhook_signature_mismatch');
        }
    }

    /**
     * Verifies, then decodes the event.
     *
     * @return array{id: string, type: string, createdAt: string, data: array<string, mixed>}
     *
     * @throws WebhookException
     */
    public static function constructEvent(
        string $payload,
        string $signature,
        string $secret,
        int $toleranceSeconds = self::DEFAULT_TOLERANCE_SECONDS,
        ?int $now = null,
    ): array {
        self::verify($payload, $signature, $secret, $toleranceSeconds, $now);
        $event = json_decode($payload, true);
        if (!is_array($event) || !is_string($event['type'] ?? null)) {
            throw new WebhookException('The webhook body is not an event.', 'webhook_malformed_signature');
        }

        /** @var array{id: string, type: string, createdAt: string, data: array<string, mixed>} $event */
        return $event;
    }
}
