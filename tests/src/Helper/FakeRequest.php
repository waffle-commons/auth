<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Helper;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;

/** Immutable PSR-7 request fake with real header semantics. */
class FakeRequest implements RequestInterface
{
    /** @var array<string, list<string>> Keyed by lowercase header name. */
    protected array $headers = [];

    protected UriInterface $uri;

    protected StreamInterface $body;

    /**
     * @param array<string, string> $headers
     */
    public function __construct(
        protected string $method = 'GET',
        ?UriInterface $uri = null,
        array $headers = [],
        ?StreamInterface $body = null,
    ) {
        $this->uri = $uri ?? new FakeUri();
        $this->body = $body ?? new FakeStream();
        foreach ($headers as $name => $value) {
            $this->headers[strtolower($name)] = [$value];
        }
    }

    #[\Override]
    public function getProtocolVersion(): string
    {
        return '1.1';
    }

    #[\Override]
    public function withProtocolVersion(string $version): static
    {
        return $this;
    }

    /**
     * @return array<string, list<string>>
     */
    #[\Override]
    public function getHeaders(): array
    {
        return $this->headers;
    }

    #[\Override]
    public function hasHeader(string $name): bool
    {
        return array_key_exists(strtolower($name), $this->headers);
    }

    /**
     * @return list<string>
     */
    #[\Override]
    public function getHeader(string $name): array
    {
        return $this->headers[strtolower($name)] ?? [];
    }

    #[\Override]
    public function getHeaderLine(string $name): string
    {
        return implode(', ', $this->getHeader($name));
    }

    #[\Override]
    public function withHeader(string $name, $value): static
    {
        $clone = clone $this;
        $clone->headers[strtolower($name)] = is_array($value) ? array_values($value) : [$value];

        return $clone;
    }

    #[\Override]
    public function withAddedHeader(string $name, $value): static
    {
        $clone = clone $this;
        $existing = $clone->headers[strtolower($name)] ?? [];
        $added = is_array($value) ? array_values($value) : [$value];
        $clone->headers[strtolower($name)] = [...$existing, ...$added];

        return $clone;
    }

    #[\Override]
    public function withoutHeader(string $name): static
    {
        $clone = clone $this;
        unset($clone->headers[strtolower($name)]);

        return $clone;
    }

    #[\Override]
    public function getBody(): StreamInterface
    {
        return $this->body;
    }

    #[\Override]
    public function withBody(StreamInterface $body): static
    {
        $clone = clone $this;
        $clone->body = $body;

        return $clone;
    }

    #[\Override]
    public function getRequestTarget(): string
    {
        return $this->uri->getPath();
    }

    #[\Override]
    public function withRequestTarget(string $requestTarget): static
    {
        return $this;
    }

    #[\Override]
    public function getMethod(): string
    {
        return $this->method;
    }

    #[\Override]
    public function withMethod(string $method): static
    {
        $clone = clone $this;
        $clone->method = $method;

        return $clone;
    }

    #[\Override]
    public function getUri(): UriInterface
    {
        return $this->uri;
    }

    #[\Override]
    public function withUri(UriInterface $uri, bool $preserveHost = false): static
    {
        $clone = clone $this;
        $clone->uri = $uri;

        return $clone;
    }
}
