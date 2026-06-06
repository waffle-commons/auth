<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth;

use PHPUnit\Framework\TestCase as BaseTestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;
use WaffleTests\Commons\Auth\Helper\FakeHttpClient;
use WaffleTests\Commons\Auth\Helper\PassHandler;

abstract class AbstractTestCase extends BaseTestCase
{
    /**
     * Returns the request the PSR-15 handler spy received, failing the test
     * when the middleware never forwarded one (type-narrowing the analyzer
     * cannot infer from `assertNotNull()`).
     */
    final protected static function received(PassHandler $handler): ServerRequestInterface
    {
        $received = $handler->received;
        if ($received === null) {
            self::fail('The handler never received a forwarded request.');
        }

        return $received;
    }

    /**
     * Returns the n-th request the PSR-18 spy sent, failing the test when
     * fewer were dispatched.
     */
    final protected static function sent(FakeHttpClient $client, int $index = 0): RequestInterface
    {
        $sent = $client->sent[$index] ?? null;
        if ($sent === null) {
            self::fail(sprintf('No request #%d was sent through the PSR-18 spy.', $index));
        }

        return $sent;
    }

    /**
     * Parses an `application/x-www-form-urlencoded` payload (or URL query
     * string) into a string map — the typed wrapper around `parse_str()`'s
     * by-reference idiom.
     *
     * @return array<string, string>
     */
    final protected static function parseForm(string $encoded): array
    {
        $parsed = [];
        parse_str($encoded, $parsed);

        $form = [];
        foreach ($parsed as $key => $value) {
            if (!is_string($value)) {
                continue;
            }

            $form[$key] = $value;
        }

        return $form;
    }
}
