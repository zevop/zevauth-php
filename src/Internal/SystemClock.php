<?php

declare(strict_types=1);

namespace ZevAuth\Internal;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/** @internal */
final class SystemClock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable();
    }
}
