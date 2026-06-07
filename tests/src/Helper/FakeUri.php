<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Helper;

use Psr\Http\Message\UriInterface;

/** Minimal immutable PSR-7 URI fake (host/path/query are what tests use). */
final class FakeUri implements UriInterface
{
    public function __construct(
        private readonly string $host = 'example.test',
        private readonly string $path = '/',
        private readonly string $query = '',
        private readonly string $scheme = 'https',
    ) {}

    #[\Override]
    public function getScheme(): string
    {
        return $this->scheme;
    }

    #[\Override]
    public function getAuthority(): string
    {
        return $this->host;
    }

    #[\Override]
    public function getUserInfo(): string
    {
        return '';
    }

    #[\Override]
    public function getHost(): string
    {
        return $this->host;
    }

    #[\Override]
    public function getPort(): null
    {
        return null;
    }

    #[\Override]
    public function getPath(): string
    {
        return $this->path;
    }

    #[\Override]
    public function getQuery(): string
    {
        return $this->query;
    }

    #[\Override]
    public function getFragment(): string
    {
        return '';
    }

    #[\Override]
    public function withScheme(string $scheme): static
    {
        return new self($this->host, $this->path, $this->query, $scheme);
    }

    #[\Override]
    public function withUserInfo(string $user, #[\SensitiveParameter] ?string $password = null): static
    {
        return $this;
    }

    #[\Override]
    public function withHost(string $host): static
    {
        return new self($host, $this->path, $this->query, $this->scheme);
    }

    #[\Override]
    public function withPort(?int $port): static
    {
        return $this;
    }

    #[\Override]
    public function withPath(string $path): static
    {
        return new self($this->host, $path, $this->query, $this->scheme);
    }

    #[\Override]
    public function withQuery(string $query): static
    {
        return new self($this->host, $this->path, $query, $this->scheme);
    }

    #[\Override]
    public function withFragment(string $fragment): static
    {
        return $this;
    }

    #[\Override]
    public function __toString(): string
    {
        $uri = $this->scheme . '://' . $this->host . $this->path;

        return $this->query === '' ? $uri : $uri . '?' . $this->query;
    }
}
