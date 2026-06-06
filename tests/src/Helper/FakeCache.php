<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Helper;

use DateInterval;
use Psr\SimpleCache\CacheInterface;

/** PSR-16 array-backed cache spy (records set TTLs). */
final class FakeCache implements CacheInterface
{
    /** @var array<string, mixed> */
    public array $store = [];

    /** @var array<string, DateInterval|int|null> */
    public array $ttls = [];

    #[\Override]
    public function get(string $key, mixed $default = null): mixed
    {
        return $this->store[$key] ?? $default;
    }

    #[\Override]
    public function set(string $key, mixed $value, DateInterval|int|null $ttl = null): bool
    {
        $this->store[$key] = $value;
        $this->ttls[$key] = $ttl;

        return true;
    }

    #[\Override]
    public function delete(string $key): bool
    {
        unset($this->store[$key], $this->ttls[$key]);

        return true;
    }

    #[\Override]
    public function clear(): bool
    {
        $this->store = [];
        $this->ttls = [];

        return true;
    }

    /**
     * @return iterable<string, mixed>
     */
    #[\Override]
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $result = [];
        foreach ($keys as $key) {
            $result[$key] = $this->get($key, $default);
        }

        return $result;
    }

    #[\Override]
    public function setMultiple(iterable $values, DateInterval|int|null $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            if (!is_string($key)) {
                continue;
            }

            $this->set($key, $value, $ttl);
        }

        return true;
    }

    #[\Override]
    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    #[\Override]
    public function has(string $key): bool
    {
        return array_key_exists($key, $this->store);
    }
}
