<?php

declare(strict_types=1);

namespace ZevAuth\Internal;

use DateInterval;
use DateTimeImmutable;
use Psr\SimpleCache\CacheInterface;

/**
 * The default key cache: this process only.
 *
 * Fine for long-running servers (RoadRunner, Swoole, Octane, workers).
 * Under PHP-FPM each request starts empty, so the keys would be fetched
 * on every request: pass a shared PSR-16 cache (APCu, Redis, Laravel's
 * cache store) there. The Laravel integration does this for you.
 *
 * @internal
 */
final class MemoryCache implements CacheInterface
{
    /** @var array<string, array{0: mixed, 1: int|null}> */
    private array $items = [];

    public function get(string $key, mixed $default = null): mixed
    {
        if (!isset($this->items[$key])) {
            return $default;
        }
        [$value, $expires] = $this->items[$key];
        if ($expires !== null && $expires <= time()) {
            unset($this->items[$key]);

            return $default;
        }

        return $value;
    }

    public function set(string $key, mixed $value, null|int|DateInterval $ttl = null): bool
    {
        $this->items[$key] = [$value, self::expiry($ttl)];

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->items[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->items = [];

        return true;
    }

    /** @param iterable<string> $keys */
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $out = [];
        foreach ($keys as $key) {
            $out[$key] = $this->get($key, $default);
        }

        return $out;
    }

    /** @param iterable<string, mixed> $values */
    public function setMultiple(iterable $values, null|int|DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set((string) $key, $value, $ttl);
        }

        return true;
    }

    /** @param iterable<string> $keys */
    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return $this->get($key, $this) !== $this;
    }

    private static function expiry(null|int|DateInterval $ttl): ?int
    {
        if ($ttl === null) {
            return null;
        }
        if ($ttl instanceof DateInterval) {
            return (new DateTimeImmutable())->add($ttl)->getTimestamp();
        }

        return time() + $ttl;
    }
}
