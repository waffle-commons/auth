<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Helper;

use DateInterval;
use Exception;
use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;

/** PSR-16 fake whose backend rejects every key (wiring-fault simulation). */
final class ThrowingCache implements CacheInterface
{
    #[\Override]
    public function get(string $key, mixed $default = null): mixed
    {
        throw new class('key rejected') extends Exception implements InvalidArgumentException {};
    }

    #[\Override]
    public function set(string $key, mixed $value, DateInterval|int|null $ttl = null): bool
    {
        throw new class('key rejected') extends Exception implements InvalidArgumentException {};
    }

    #[\Override]
    public function delete(string $key): bool
    {
        return false;
    }

    #[\Override]
    public function clear(): bool
    {
        return false;
    }

    /**
     * @return iterable<string, mixed>
     */
    #[\Override]
    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        return [];
    }

    #[\Override]
    public function setMultiple(iterable $values, DateInterval|int|null $ttl = null): bool
    {
        return false;
    }

    #[\Override]
    public function deleteMultiple(iterable $keys): bool
    {
        return false;
    }

    #[\Override]
    public function has(string $key): bool
    {
        return false;
    }
}
