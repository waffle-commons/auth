<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Helper;

use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;

/** PSR-17 fakes producing the in-memory PSR-7 fakes. */
final class FakeFactories implements RequestFactoryInterface, StreamFactoryInterface
{
    #[\Override]
    public function createRequest(string $method, $uri): RequestInterface
    {
        $parsedHost = is_string($uri) ? (string) parse_url($uri, PHP_URL_HOST) : 'example.test';
        $parsedPath = is_string($uri) ? (string) parse_url($uri, PHP_URL_PATH) : '/';

        return new FakeRequest(
            method: $method,
            uri: new FakeUri(host: $parsedHost === '' ? 'example.test' : $parsedHost, path: $parsedPath),
        );
    }

    #[\Override]
    public function createStream(string $content = ''): StreamInterface
    {
        return new FakeStream($content);
    }

    #[\Override]
    public function createStreamFromFile(string $filename, string $mode = 'r'): StreamInterface
    {
        return new FakeStream();
    }

    #[\Override]
    public function createStreamFromResource($resource): StreamInterface
    {
        return new FakeStream();
    }
}
