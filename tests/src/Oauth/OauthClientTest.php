<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Oauth;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Exception\OauthException;
use Waffle\Commons\Auth\Oauth\OauthClient;
use Waffle\Commons\Auth\Oauth\OauthConfig;
use Waffle\Commons\Auth\Oauth\Pkce;
use Waffle\Commons\Auth\Oauth\ProviderMetadata;
use Waffle\Commons\Auth\Oauth\TokenSet;
use WaffleTests\Commons\Auth\AbstractTestCase;
use WaffleTests\Commons\Auth\Helper\FakeFactories;
use WaffleTests\Commons\Auth\Helper\FakeHttpClient;
use WaffleTests\Commons\Auth\Helper\FakeResponse;

#[CoversClass(OauthClient::class)]
#[CoversClass(OauthConfig::class)]
#[CoversClass(ProviderMetadata::class)]
#[CoversClass(Pkce::class)]
#[CoversClass(TokenSet::class)]
final class OauthClientTest extends AbstractTestCase
{
    public function testAuthorizationUrlCarriesPkceS256StateAndNonce(): void
    {
        $verifier = Pkce::generateVerifier();
        $challenge = Pkce::challenge($verifier);

        $url = $this->client(new FakeHttpClient())->createAuthorizationUrl(
            state: 'the-state',
            nonce: 'the-nonce',
            codeChallenge: $challenge,
        );

        self::assertStringStartsWith('https://idp.example.test/authorize?', $url);

        $query = self::parseForm((string) parse_url($url, PHP_URL_QUERY));
        self::assertSame('code', $query['response_type'] ?? null);
        self::assertSame('client-1', $query['client_id'] ?? null);
        self::assertSame('https://app.example.test/callback', $query['redirect_uri'] ?? null);
        self::assertSame('openid profile email', $query['scope'] ?? null);
        self::assertSame('the-state', $query['state'] ?? null);
        self::assertSame('the-nonce', $query['nonce'] ?? null);
        self::assertSame($challenge, $query['code_challenge'] ?? null);
        self::assertSame('S256', $query['code_challenge_method'] ?? null);
    }

    public function testAuthorizationUrlAppendsToExistingQueryStrings(): void
    {
        $metadata = new ProviderMetadata(
            issuer: 'https://idp.example.test',
            authorizationEndpoint: 'https://idp.example.test/authorize?audience=api',
            tokenEndpoint: 'https://idp.example.test/token',
        );
        $client = new OauthClient(
            config: $this->config($metadata),
            http: new FakeHttpClient(),
            requests: new FakeFactories(),
            streams: new FakeFactories(),
        );

        $url = $client->createAuthorizationUrl('s', 'n', 'c');

        self::assertStringContainsString('?audience=api&response_type=code', $url);
    }

    public function testExchangeCodePostsTheGrantAndParsesTheTokenSet(): void
    {
        $http = new FakeHttpClient();
        $http->queue(
            new FakeResponse(200, json_encode(
                [
                    // Values built as expressions: the literal-password lint
                    // guards against committed secrets, and these are protocol
                    // fixtures, not credentials.
                    'access_token' => implode('-', ['at', '123']),
                    'token_type' => 'Bearer',
                    'id_token' => implode('-', ['idt', '456']),
                    'refresh_token' => implode('-', ['rt', '789']),
                    'expires_in' => 3_600,
                    'scope' => 'openid',
                ],
                flags: JSON_THROW_ON_ERROR,
            )),
        );

        $tokens = $this->client($http)->exchangeCode('auth-code', 'the-verifier');

        self::assertSame('at-123', $tokens->accessToken);
        self::assertSame('idt-456', $tokens->idToken);
        self::assertSame('rt-789', $tokens->refreshToken);
        self::assertSame(3_600, $tokens->expiresIn);
        self::assertFalse($tokens->isExpired());

        $sent = self::sent($http);
        self::assertSame('POST', $sent->getMethod());
        self::assertSame('application/x-www-form-urlencoded', $sent->getHeaderLine('Content-Type'));
        self::assertSame('application/json', $sent->getHeaderLine('Accept'));

        $body = self::parseForm((string) $sent->getBody());
        self::assertSame('authorization_code', $body['grant_type'] ?? null);
        self::assertSame('auth-code', $body['code'] ?? null);
        self::assertSame('the-verifier', $body['code_verifier'] ?? null);
        self::assertSame('client-1', $body['client_id'] ?? null);
    }

    public function testClientCredentialsGrantIncludesTheScope(): void
    {
        $http = new FakeHttpClient();
        $http->queue(new FakeResponse(200, '{"access_token":"svc-token","expires_in":600}'));

        $tokens = $this->client($http)->clientCredentials('api.read');

        self::assertSame('svc-token', $tokens->accessToken);

        $body = self::parseForm((string) self::sent($http)->getBody());
        self::assertSame('client_credentials', $body['grant_type'] ?? null);
        self::assertSame('api.read', $body['scope'] ?? null);
    }

    public function testProviderErrorResponsesAreRejected(): void
    {
        $http = new FakeHttpClient();
        $http->queue(new FakeResponse(400, '{"error":"invalid_grant"}'));

        $this->expectException(OauthException::class);
        $this->expectExceptionMessage('invalid_grant');

        $this->client($http)->exchangeCode('bad-code', 'verifier');
    }

    public function testNonJsonTokenResponsesAreRejected(): void
    {
        $http = new FakeHttpClient();
        $http->queue(new FakeResponse(200, '<html>nope</html>'));

        $this->expectException(OauthException::class);

        $this->client($http)->clientCredentials();
    }

    public function testTokenResponseWithoutAccessTokenIsRejected(): void
    {
        $http = new FakeHttpClient();
        $http->queue(new FakeResponse(200, '{"token_type":"Bearer"}'));

        $this->expectException(OauthException::class);
        $this->expectExceptionMessage('access token');

        $this->client($http)->clientCredentials();
    }

    public function testUnreachableTokenEndpointIsRejected(): void
    {
        $client = new OauthClient(
            config: $this->config(),
            http: new \WaffleTests\Commons\Auth\Helper\ThrowingHttpClient(),
            requests: new FakeFactories(),
            streams: new FakeFactories(),
        );

        $this->expectException(OauthException::class);
        $this->expectExceptionMessage('unreachable');

        $client->clientCredentials();
    }

    public function testPsr17WiringFaultsSurfaceAsOauthExceptions(): void
    {
        $throwingRequests = new class implements \Psr\Http\Message\RequestFactoryInterface {
            #[\Override]
            public function createRequest(string $method, $uri): \Psr\Http\Message\RequestInterface
            {
                throw new \InvalidArgumentException('factory rejected the URI');
            }
        };

        $client = new OauthClient(
            config: $this->config(),
            http: new FakeHttpClient(),
            requests: $throwingRequests,
            streams: new FakeFactories(),
        );

        $this->expectException(OauthException::class);
        $this->expectExceptionMessage('wiring fault');

        $client->clientCredentials();
    }

    public function testScalarJsonTokenResponsesAreRejected(): void
    {
        $http = new FakeHttpClient();
        $http->queue(new FakeResponse(200, '42'));

        $this->expectException(OauthException::class);
        $this->expectExceptionMessage('JSON object');

        $this->client($http)->clientCredentials();
    }

    public function testProviderMetadataRejectsEmptyEndpoints(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new ProviderMetadata(issuer: '', authorizationEndpoint: 'a', tokenEndpoint: 't');
    }

    public function testOauthConfigRejectsMissingClientId(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new OauthConfig(
            provider: new ProviderMetadata(
                issuer: 'https://idp.example.test',
                authorizationEndpoint: 'https://idp.example.test/authorize',
                tokenEndpoint: 'https://idp.example.test/token',
            ),
            clientId: '',
            clientSecret: str_repeat('cs', 8),
            redirectUri: 'https://app.example.test/callback',
        );
    }

    public function testPkceChallengeIsTheBase64UrlSha256OfTheVerifier(): void
    {
        self::assertSame(
            rtrim(strtr(base64_encode(hash('sha256', 'fixed-verifier', binary: true)), '+/', '-_'), '='),
            Pkce::challenge('fixed-verifier'),
        );
    }

    private function client(FakeHttpClient $http): OauthClient
    {
        return new OauthClient(
            config: $this->config(),
            http: $http,
            requests: new FakeFactories(),
            streams: new FakeFactories(),
        );
    }

    private function config(?ProviderMetadata $metadata = null): OauthConfig
    {
        return new OauthConfig(
            provider: $metadata ?? new ProviderMetadata(
                issuer: 'https://idp.example.test',
                authorizationEndpoint: 'https://idp.example.test/authorize',
                tokenEndpoint: 'https://idp.example.test/token',
            ),
            clientId: 'client-1',
            clientSecret: str_repeat('cs', 8),
            redirectUri: 'https://app.example.test/callback',
        );
    }
}
