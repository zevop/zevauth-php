<?php

declare(strict_types=1);

namespace ZevAuth\Tests\Support;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * Reads the shared conformance fixtures (tests/fixtures, copied from the
 * ZevAuth server-SDK contract).
 */
final class Fixtures
{
    /** @return array<string, mixed> */
    public static function load(string $name): array
    {
        $raw = file_get_contents(__DIR__ . '/../fixtures/' . $name);
        if ($raw === false) {
            throw new \RuntimeException("Missing fixture {$name}. Run composer sync-fixtures.");
        }

        return json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
    }

    public static function clock(int $now): ClockInterface
    {
        return new class ($now) implements ClockInterface {
            public function __construct(private int $now)
            {
            }

            public function now(): DateTimeImmutable
            {
                return (new DateTimeImmutable())->setTimestamp($this->now);
            }
        };
    }
}
