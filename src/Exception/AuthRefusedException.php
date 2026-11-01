<?php

declare(strict_types=1);

namespace ZevAuth\Exception;

/**
 * `requireAuth()` refused the request.
 *
 * | status | errorCode              | when                                   |
 * | ------ | ---------------------- | -------------------------------------- |
 * | 401    | `unauthorized`         | nobody is signed in                    |
 * | 403    | `session_task_pending` | the session has unfinished tasks       |
 * | 403    | `mfa_required`         | `requireMfa` and no second factor      |
 *
 * `toArray()` is the response body every ZevAuth integration sends, the
 * same envelope the ZevAuth API uses.
 */
final class AuthRefusedException extends ZevAuthException
{
    /**
     * @param list<string> $pendingTasks
     */
    public function __construct(
        string $message,
        string $errorCode,
        public readonly int $status,
        public readonly array $pendingTasks = [],
    ) {
        parent::__construct($message, $errorCode);
    }

    /**
     * @return array{error: array<string, mixed>}
     */
    public function toArray(): array
    {
        $error = ['code' => $this->errorCode, 'message' => $this->getMessage()];
        if ($this->errorCode === 'session_task_pending') {
            $error['pendingTasks'] = $this->pendingTasks;
        }

        return ['error' => $error];
    }
}
