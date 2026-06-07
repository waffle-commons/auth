<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Helper;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;

/** Immutable PSR-7 server-request fake (server params + attributes). */
final class FakeServerRequest extends FakeRequest implements ServerRequestInterface
{
    /** @var array<string, mixed> */
    private array $attributes = [];

    /**
     * @param array<string, string> $headers
     * @param array<string, mixed>  $serverParams
     */
    public function __construct(
        string $method = 'GET',
        ?UriInterface $uri = null,
        array $headers = [],
        private readonly array $serverParams = [],
    ) {
        parent::__construct(method: $method, uri: $uri, headers: $headers);
    }

    /**
     * @return array<string, mixed>
     */
    #[\Override]
    public function getServerParams(): array
    {
        return $this->serverParams;
    }

    /**
     * @return array<string, string>
     */
    #[\Override]
    public function getCookieParams(): array
    {
        return [];
    }

    #[\Override]
    public function withCookieParams(array $cookies): static
    {
        return $this;
    }

    /**
     * @return array<string, string>
     */
    #[\Override]
    public function getQueryParams(): array
    {
        return [];
    }

    #[\Override]
    public function withQueryParams(array $query): static
    {
        return $this;
    }

    /**
     * @return list<mixed>
     */
    #[\Override]
    public function getUploadedFiles(): array
    {
        return [];
    }

    #[\Override]
    public function withUploadedFiles(array $uploadedFiles): static
    {
        return $this;
    }

    #[\Override]
    public function getParsedBody(): null
    {
        return null;
    }

    #[\Override]
    public function withParsedBody($data): static
    {
        return $this;
    }

    /**
     * @return array<string, mixed>
     */
    #[\Override]
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    #[\Override]
    public function getAttribute(string $name, $default = null): mixed
    {
        return $this->attributes[$name] ?? $default;
    }

    #[\Override]
    public function withAttribute(string $name, $value): static
    {
        $clone = clone $this;
        $clone->attributes[$name] = $value;

        return $clone;
    }

    #[\Override]
    public function withoutAttribute(string $name): static
    {
        $clone = clone $this;
        unset($clone->attributes[$name]);

        return $clone;
    }
}
