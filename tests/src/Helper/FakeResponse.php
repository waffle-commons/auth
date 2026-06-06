<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Helper;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

/** Minimal PSR-7 response fake (status + JSON body are what tests use). */
final class FakeResponse implements ResponseInterface
{
    private readonly StreamInterface $body;

    public function __construct(
        private readonly int $statusCode = 200,
        string $body = '',
    ) {
        $this->body = new FakeStream($body);
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
        return [];
    }

    #[\Override]
    public function hasHeader(string $name): bool
    {
        return false;
    }

    /**
     * @return list<string>
     */
    #[\Override]
    public function getHeader(string $name): array
    {
        return [];
    }

    #[\Override]
    public function getHeaderLine(string $name): string
    {
        return '';
    }

    #[\Override]
    public function withHeader(string $name, $value): static
    {
        return $this;
    }

    #[\Override]
    public function withAddedHeader(string $name, $value): static
    {
        return $this;
    }

    #[\Override]
    public function withoutHeader(string $name): static
    {
        return $this;
    }

    #[\Override]
    public function getBody(): StreamInterface
    {
        return $this->body;
    }

    #[\Override]
    public function withBody(StreamInterface $body): static
    {
        return $this;
    }

    #[\Override]
    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    #[\Override]
    public function withStatus(int $code, string $reasonPhrase = ''): static
    {
        return new self($code, (string) $this->body);
    }

    #[\Override]
    public function getReasonPhrase(): string
    {
        return '';
    }
}
