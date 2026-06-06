<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Credential;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Credential\ClientCredentialsProvider;
use Waffle\Commons\Auth\Oauth\OauthClient;
use Waffle\Commons\Auth\Oauth\OauthConfig;
use Waffle\Commons\Auth\Oauth\ProviderMetadata;
use Waffle\Commons\Contracts\Auth\Constant;
use WaffleTests\Commons\Auth\AbstractTestCase;
use WaffleTests\Commons\Auth\Helper\FakeCache;
use WaffleTests\Commons\Auth\Helper\FakeFactories;
use WaffleTests\Commons\Auth\Helper\FakeHttpClient;
use WaffleTests\Commons\Auth\Helper\FakeRequest;
use WaffleTests\Commons\Auth\Helper\FakeResponse;
use WaffleTests\Commons\Auth\Helper\FakeUri;

#[CoversClass(ClientCredentialsProvider::class)]
final class ClientCredentialsProviderTest extends AbstractTestCase
{
    public function testAcquiresCachesAndReusesTheServiceToken(): void
    {
        $idpTransport = new FakeHttpClient();
        $idpTransport->queue(new FakeResponse(200, '{"access_token":"svc-token","expires_in":600}'));

        $cache = new FakeCache();
        $provider = new ClientCredentialsProvider(
            oauth: $this->oauth($idpTransport),
            cache: $cache,
            allowedHosts: ['api.example.test'],
            scope: 'api.read',
        );

        $request = new FakeRequest(uri: new FakeUri(host: 'api.example.test'));

        // First call: grant + cache (expires_in 600 − 30s margin = 570).
        $first = $provider->apply($request);
        self::assertSame('Bearer svc-token', $first->getHeaderLine(Constant::AUTHORIZATION_HEADER));
        self::assertCount(1, $idpTransport->sent);
        self::assertSame([570], array_values($cache->ttls));

        // Second call: served from the cache, no new grant.
        $second = $provider->apply($request);
        self::assertSame('Bearer svc-token', $second->getHeaderLine(Constant::AUTHORIZATION_HEADER));
        self::assertCount(1, $idpTransport->sent);
    }

    public function testDoesNotTouchUnrelatedHosts(): void
    {
        $provider = new ClientCredentialsProvider(
            oauth: $this->oauth(new FakeHttpClient()),
            cache: new FakeCache(),
            allowedHosts: ['api.example.test'],
        );

        self::assertFalse($provider->supports(new FakeRequest(uri: new FakeUri(host: 'other.example.test'))));
    }

    public function testNeverOverwritesAnExistingAuthorizationHeader(): void
    {
        $provider = new ClientCredentialsProvider(
            oauth: $this->oauth(new FakeHttpClient()),
            cache: new FakeCache(),
            allowedHosts: ['api.example.test'],
        );

        $request = new FakeRequest(uri: new FakeUri(host: 'api.example.test'), headers: [
            Constant::AUTHORIZATION_HEADER => 'Bearer existing',
        ]);

        self::assertSame('Bearer existing', $provider->apply($request)->getHeaderLine(Constant::AUTHORIZATION_HEADER));
    }

    public function testTokensWithoutLifetimeAreCachedWithoutTtl(): void
    {
        $idpTransport = new FakeHttpClient();
        $idpTransport->queue(new FakeResponse(200, '{"access_token":"svc-token"}'));

        $cache = new FakeCache();
        $provider = new ClientCredentialsProvider(
            oauth: $this->oauth($idpTransport),
            cache: $cache,
            allowedHosts: ['api.example.test'],
        );

        $provider->apply(new FakeRequest(uri: new FakeUri(host: 'api.example.test')));

        self::assertSame([null], array_values($cache->ttls));
    }

    public function testCacheBackendRejectingItsKeyIsAWiringFault(): void
    {
        $provider = new ClientCredentialsProvider(
            oauth: $this->oauth(new FakeHttpClient()),
            cache: new \WaffleTests\Commons\Auth\Helper\ThrowingCache(),
            allowedHosts: ['api.example.test'],
        );

        $this->expectException(\Waffle\Commons\Auth\Exception\OauthException::class);
        $this->expectExceptionMessage('cache');

        $provider->apply(new FakeRequest(uri: new FakeUri(host: 'api.example.test')));
    }

    private function oauth(FakeHttpClient $http): OauthClient
    {
        return new OauthClient(
            config: new OauthConfig(
                provider: new ProviderMetadata(
                    issuer: 'https://idp.example.test',
                    authorizationEndpoint: 'https://idp.example.test/authorize',
                    tokenEndpoint: 'https://idp.example.test/token',
                ),
                clientId: 'client-1',
                clientSecret: str_repeat('cs', 8),
                redirectUri: 'https://app.example.test/callback',
            ),
            http: $http,
            requests: new FakeFactories(),
            streams: new FakeFactories(),
        );
    }
}
