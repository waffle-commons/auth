<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Credential;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Credential\ApiKeyCredentialsProvider;
use Waffle\Commons\Auth\Credential\BasicCredentialsProvider;
use Waffle\Commons\Auth\Credential\BearerCredentialsProvider;
use Waffle\Commons\Contracts\Auth\Constant;
use WaffleTests\Commons\Auth\AbstractTestCase;
use WaffleTests\Commons\Auth\Helper\FakeRequest;
use WaffleTests\Commons\Auth\Helper\FakeUri;

#[CoversClass(BearerCredentialsProvider::class)]
#[CoversClass(ApiKeyCredentialsProvider::class)]
#[CoversClass(BasicCredentialsProvider::class)]
final class CredentialsProvidersTest extends AbstractTestCase
{
    public function testBearerAttachesTheTokenToAllowedHosts(): void
    {
        $provider = new BearerCredentialsProvider('the-token', ['api.example.test']);
        $request = new FakeRequest(uri: new FakeUri(host: 'api.example.test'));

        self::assertTrue($provider->supports($request));
        self::assertSame('Bearer the-token', $provider->apply($request)->getHeaderLine(Constant::AUTHORIZATION_HEADER));
    }

    public function testBearerHostMatchingIsCaseInsensitive(): void
    {
        $provider = new BearerCredentialsProvider('t', ['api.example.test']);

        self::assertTrue($provider->supports(new FakeRequest(uri: new FakeUri(host: 'API.EXAMPLE.TEST'))));
        self::assertFalse($provider->supports(new FakeRequest(uri: new FakeUri(host: 'other.example.test'))));
    }

    public function testConfiguredHostsAreNormalizedToLowercase(): void
    {
        // A mixed-case allow-list entry must still gate a lowercase request
        // host — the provider normalizes the configured list at construction.
        $provider = new BearerCredentialsProvider('the-token', ['API.Example.TEST']);

        self::assertSame(
            'Bearer the-token',
            $provider
                ->apply(new FakeRequest(uri: new FakeUri(host: 'api.example.test')))
                ->getHeaderLine(Constant::AUTHORIZATION_HEADER),
        );
    }

    public function testEmptyBearerTokenIsNeverAttached(): void
    {
        $provider = new BearerCredentialsProvider('', ['api.example.test']);
        $request = new FakeRequest(uri: new FakeUri(host: 'api.example.test'));

        self::assertFalse($provider->apply($request)->hasHeader(Constant::AUTHORIZATION_HEADER));
    }

    public function testApiKeyUsesTheConfiguredHeader(): void
    {
        $provider = new ApiKeyCredentialsProvider('the-key', ['api.example.test'], headerName: 'X-Custom');
        $request = new FakeRequest(uri: new FakeUri(host: 'api.example.test'));

        self::assertSame('the-key', $provider->apply($request)->getHeaderLine('X-Custom'));
    }

    public function testApiKeyNeverOverwrites(): void
    {
        $provider = new ApiKeyCredentialsProvider('injected', ['api.example.test']);
        $request = new FakeRequest(uri: new FakeUri(host: 'api.example.test'), headers: [
            Constant::API_KEY_HEADER => 'caller-supplied',
        ]);

        self::assertSame('caller-supplied', $provider->apply($request)->getHeaderLine(Constant::API_KEY_HEADER));
    }

    public function testBasicEncodesUserAndPassword(): void
    {
        $provider = new BasicCredentialsProvider('ada', 's3cret', ['api.example.test']);
        $request = new FakeRequest(uri: new FakeUri(host: 'api.example.test'));

        self::assertSame(
            Constant::BASIC_PREFIX . base64_encode('ada:s3cret'),
            $provider->apply($request)->getHeaderLine(Constant::AUTHORIZATION_HEADER),
        );
    }

    public function testBasicIsHostGated(): void
    {
        $provider = new BasicCredentialsProvider('ada', 's3cret', ['api.example.test']);

        self::assertTrue($provider->supports(new FakeRequest(uri: new FakeUri(host: 'api.example.test'))));
        self::assertFalse($provider->supports(new FakeRequest(uri: new FakeUri(host: 'other.example.test'))));
    }

    public function testBasicNeverOverwrites(): void
    {
        $provider = new BasicCredentialsProvider('ada', 's3cret', ['api.example.test']);
        $request = new FakeRequest(uri: new FakeUri(host: 'api.example.test'), headers: [
            Constant::AUTHORIZATION_HEADER => 'Bearer existing',
        ]);

        self::assertSame('Bearer existing', $provider->apply($request)->getHeaderLine(Constant::AUTHORIZATION_HEADER));
    }
}
