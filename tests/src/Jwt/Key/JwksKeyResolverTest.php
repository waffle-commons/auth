<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Jwt\Key;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Exception\InvalidTokenException;
use Waffle\Commons\Auth\Jwt\Key\JwkConverter;
use Waffle\Commons\Auth\Jwt\Key\JwksKeyResolver;
use WaffleTests\Commons\Auth\AbstractTestCase;
use WaffleTests\Commons\Auth\Helper\FakeCache;
use WaffleTests\Commons\Auth\Helper\FakeFactories;
use WaffleTests\Commons\Auth\Helper\FakeHttpClient;
use WaffleTests\Commons\Auth\Helper\FakeResponse;
use WaffleTests\Commons\Auth\Helper\JwtMinter;

#[CoversClass(JwksKeyResolver::class)]
#[CoversClass(JwkConverter::class)]
final class JwksKeyResolverTest extends AbstractTestCase
{
    private const string JWKS_URI = 'https://idp.example.test/jwks.json';

    public function testFetchesSelectsByKidConvertsAndCaches(): void
    {
        $pair = JwtMinter::rsaKeyPair();
        $http = new FakeHttpClient();
        $http->queue(
            new FakeResponse(200, json_encode([
                'keys' => [
                    ['kty' => 'oct', 'kid' => 'symmetric-ignored'],
                    ['kty' => 'RSA', 'kid' => 'key-1', 'n' => $pair->modulus, 'e' => $pair->exponent],
                ],
            ], flags: JSON_THROW_ON_ERROR)),
        );

        $cache = new FakeCache();
        $resolver = new JwksKeyResolver(self::JWKS_URI, $http, new FakeFactories(), $cache, cacheTtl: 900);

        $pem = $resolver->resolve('RS256', 'key-1');

        self::assertStringContainsString('BEGIN PUBLIC KEY', $pem);
        self::assertCount(1, $http->sent, 'First resolution hits the network.');
        self::assertSame([900], array_values($cache->ttls), 'JWKS document is cached with the bounded TTL.');

        // Second resolution must be served from the cache.
        $resolver->resolve('RS256', 'key-1');
        self::assertCount(1, $http->sent);
    }

    public function testRejectsNonRs256Algorithms(): void
    {
        $resolver = new JwksKeyResolver(self::JWKS_URI, new FakeHttpClient(), new FakeFactories(), new FakeCache());

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('RS256');

        $resolver->resolve('HS256');
    }

    public function testRejectsUnknownKid(): void
    {
        $pair = JwtMinter::rsaKeyPair();
        $http = new FakeHttpClient();
        $http->queue(
            new FakeResponse(200, json_encode([
                'keys' => [['kty' => 'RSA', 'kid' => 'key-1', 'n' => $pair->modulus, 'e' => $pair->exponent]],
            ], flags: JSON_THROW_ON_ERROR)),
        );

        $resolver = new JwksKeyResolver(self::JWKS_URI, $http, new FakeFactories(), new FakeCache());

        $this->expectException(InvalidTokenException::class);

        $resolver->resolve('RS256', 'key-unknown');
    }

    public function testSkipsRsaEntriesWithoutUsableMembers(): void
    {
        $pair = JwtMinter::rsaKeyPair();
        $http = new FakeHttpClient();
        $http->queue(
            new FakeResponse(200, json_encode(
                [
                    'keys' => [
                        ['kty' => 'RSA'], // No n/e members — must be skipped.
                        ['kty' => 'RSA', 'n' => $pair->modulus, 'e' => $pair->exponent],
                    ],
                ],
                flags: JSON_THROW_ON_ERROR,
            )),
        );

        $resolver = new JwksKeyResolver(self::JWKS_URI, $http, new FakeFactories(), new FakeCache());

        self::assertStringContainsString('BEGIN PUBLIC KEY', $resolver->resolve('RS256'));
    }

    public function testSelectsTheFirstRsaKeyWhenTheTokenCarriesNoKid(): void
    {
        $pair = JwtMinter::rsaKeyPair();
        $http = new FakeHttpClient();
        $http->queue(
            new FakeResponse(200, json_encode([
                'keys' => [['kty' => 'RSA', 'n' => $pair->modulus, 'e' => $pair->exponent]],
            ], flags: JSON_THROW_ON_ERROR)),
        );

        $resolver = new JwksKeyResolver(self::JWKS_URI, $http, new FakeFactories(), new FakeCache());

        self::assertStringContainsString('BEGIN PUBLIC KEY', $resolver->resolve('RS256'));
    }

    public function testUnreachableJwksEndpointIsRejected(): void
    {
        $resolver = new JwksKeyResolver(
            self::JWKS_URI,
            new \WaffleTests\Commons\Auth\Helper\ThrowingHttpClient(),
            new FakeFactories(),
            new FakeCache(),
        );

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('unreachable');

        $resolver->resolve('RS256');
    }

    public function testCacheBackendRejectingItsKeyIsAWiringFault(): void
    {
        $resolver = new JwksKeyResolver(
            self::JWKS_URI,
            new FakeHttpClient(),
            new FakeFactories(),
            new \WaffleTests\Commons\Auth\Helper\ThrowingCache(),
        );

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('cache');

        $resolver->resolve('RS256');
    }

    public function testRejectsNon200JwksEndpoint(): void
    {
        $http = new FakeHttpClient();
        $http->queue(new FakeResponse(500, 'oops'));

        $resolver = new JwksKeyResolver(self::JWKS_URI, $http, new FakeFactories(), new FakeCache());

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('HTTP 500');

        $resolver->resolve('RS256');
    }

    public function testRejectsMalformedJwksJson(): void
    {
        $http = new FakeHttpClient();
        $http->queue(new FakeResponse(200, 'not-json'));

        $resolver = new JwksKeyResolver(self::JWKS_URI, $http, new FakeFactories(), new FakeCache());

        $this->expectException(InvalidTokenException::class);

        $resolver->resolve('RS256');
    }

    public function testRejectsDocumentWithoutKeysMember(): void
    {
        $http = new FakeHttpClient();
        $http->queue(new FakeResponse(200, '{"nope": true}'));

        $resolver = new JwksKeyResolver(self::JWKS_URI, $http, new FakeFactories(), new FakeCache());

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('keys');

        $resolver->resolve('RS256');
    }
}
