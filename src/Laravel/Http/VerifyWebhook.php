<?php

declare(strict_types=1);

namespace ZevAuth\Laravel\Http;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use ZevAuth\Exception\WebhookException;
use ZevAuth\Webhooks\Webhook;

/**
 * The `zevauth.webhook` middleware: refuses deliveries ZevAuth did not
 * sign, and hands the verified event to your controller.
 *
 *     Route::zevauthWebhooks('/webhooks/zevauth', HandleZevAuthEvent::class);
 *
 *     public function __invoke(Request $request) {
 *         $event = $request->attributes->get('zevauth.event'); // verified
 *     }
 *
 * It checks the raw body (`$request->getContent()`), which is what the
 * signature covers.
 */
final class VerifyWebhook
{
    public function __construct(private readonly Repository $config)
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $secret = (string) $this->config->get('zevauth.webhook_secret');
        if ($secret === '') {
            return new JsonResponse(['error' => ['code' => 'webhook_not_configured', 'message' => 'Set ZEVAUTH_WEBHOOK_SECRET to receive ZevAuth webhooks.']], 500);
        }

        try {
            $event = Webhook::constructEvent(
                (string) $request->getContent(),
                (string) $request->headers->get(Webhook::SIGNATURE_HEADER, ''),
                $secret,
            );
        } catch (WebhookException $e) {
            return new JsonResponse(['error' => ['code' => $e->errorCode, 'message' => $e->getMessage()]], 400);
        }

        $request->attributes->set('zevauth.event', $event);

        return $next($request);
    }
}
