<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Oauth;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Exception\OauthException;
use Waffle\Commons\Auth\Oauth\OidcDiscovery;
use WaffleTests\Commons\Auth\AbstractTestCase;
use WaffleTests\Commons\Auth\Helper\FakeCache;
use WaffleTests\Commons\Auth\Helper\FakeFactories;
use WaffleTests\Commons\Auth\Helper\FakeHttpClient;
use WaffleTests\Commons\Auth\Helper\FakeResponse;
use WaffleTests\Commons\Auth\Helper\ThrowingCache;
use WaffleTests\Commons\Auth\Helper\ThrowingHttpClient;

#[CoversClass(OidcDiscovery::class)]
final class OidcDiscoveryTest extends AbstractTestCase
{
    private const string ISSUER = 'https://idp.example.test';

    public function testResolvesAndCachesTheDiscoveryDocument(): void
    {
        $http = new FakeHttpClient();
        $http->queue(new FakeResponse(200, $this->document()));
        $cache = new FakeCache();

        $discovery = new OidcDiscovery($http, new FakeFactories(), $cache, cacheTtl: 1_200);

        $metadata = $discovery->discover(self::ISSUER . '/');

        self::assertSame(self::ISSUER, $metadata->issuer);
        self::assertSame(self::ISSUER . '/authorize', $metadata->authorizationEndpoint);
        self::assertSame(self::ISSUER . '/token', $metadata->tokenEndpoint);
        self::assertSame(self::ISSUER . '/jwks.json', $metadata->jwksUri);
        self::assertSame(self::ISSUER . '/userinfo', $metadata->userinfoEndpoint);

        self::assertCount(1, $http->sent);
        self::assertStringContainsString('/.well-known/openid-configuration', (string) self::sent($http)->getUri());
        self::assertSame([1_200], array_values($cache->ttls));

        // Second discovery is served from the cache.
        $discovery->discover(self::ISSUER);
        self::assertCount(1, $http->sent);
    }

    public function testIssuerMismatchIsRejectedAsImpersonation(): void
    {
        $http = new FakeHttpClient();
        $http->queue(
            new FakeResponse(200, json_encode([
                'issuer' => 'https://evil.example.test',
                'authorization_endpoint' => self::ISSUER . '/authorize',
                'token_endpoint' => self::ISSUER . '/token',
            ], flags: JSON_THROW_ON_ERROR)),
        );

        $discovery = new OidcDiscovery($http, new FakeFactories(), new FakeCache());

        $this->expectException(OauthException::class);
        $this->expectExceptionMessage('impersonation');

        $discovery->discover(self::ISSUER);
    }

    public function testNon200DiscoveryIsRejected(): void
    {
        $http = new FakeHttpClient();
        $http->queue(new FakeResponse(404, ''));

        $this->expectException(OauthException::class);
        $this->expectExceptionMessage('HTTP 404');

        new OidcDiscovery($http, new FakeFactories(), new FakeCache())->discover(self::ISSUER);
    }

    public function testMalformedDocumentIsRejected(): void
    {
        $http = new FakeHttpClient();
        $http->queue(new FakeResponse(200, '{"issuer": 42}'));

        $this->expectException(OauthException::class);
        $this->expectExceptionMessage('mandatory');

        new OidcDiscovery($http, new FakeFactories(), new FakeCache())->discover(self::ISSUER);
    }

    public function testNonJsonDocumentIsRejected(): void
    {
        $http = new FakeHttpClient();
        $http->queue(new FakeResponse(200, 'not-json'));

        $this->expectException(OauthException::class);

        new OidcDiscovery($http, new FakeFactories(), new FakeCache())->discover(self::ISSUER);
    }

    public function testScalarJsonDocumentIsRejected(): void
    {
        $http = new FakeHttpClient();
        $http->queue(new FakeResponse(200, '42'));

        $this->expectException(OauthException::class);
        $this->expectExceptionMessage('JSON object');

        new OidcDiscovery($http, new FakeFactories(), new FakeCache())->discover(self::ISSUER);
    }

    public function testUnreachableProviderIsRejected(): void
    {
        $discovery = new OidcDiscovery(new ThrowingHttpClient(), new FakeFactories(), new FakeCache());

        $this->expectException(OauthException::class);
        $this->expectExceptionMessage('unreachable');

        $discovery->discover(self::ISSUER);
    }

    public function testCacheBackendRejectingItsKeyIsAWiringFault(): void
    {
        $discovery = new OidcDiscovery(new FakeHttpClient(), new FakeFactories(), new ThrowingCache());

        $this->expectException(OauthException::class);
        $this->expectExceptionMessage('cache');

        $discovery->discover(self::ISSUER);
    }

    public function testEmptyMandatoryMembersAreRejected(): void
    {
        $http = new FakeHttpClient();
        $http->queue(
            new FakeResponse(200, json_encode([
                'issuer' => self::ISSUER,
                'authorization_endpoint' => '',
                'token_endpoint' => self::ISSUER . '/token',
            ], flags: JSON_THROW_ON_ERROR)),
        );

        $this->expectException(OauthException::class);
        $this->expectExceptionMessage('empty mandatory');

        new OidcDiscovery($http, new FakeFactories(), new FakeCache())->discover(self::ISSUER);
    }

    private function document(): string
    {
        return json_encode([
            'issuer' => self::ISSUER,
            'authorization_endpoint' => self::ISSUER . '/authorize',
            'token_endpoint' => self::ISSUER . '/token',
            'jwks_uri' => self::ISSUER . '/jwks.json',
            'userinfo_endpoint' => self::ISSUER . '/userinfo',
        ], flags: JSON_THROW_ON_ERROR);
    }
}
