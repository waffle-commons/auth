<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Client;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Client\AuthenticatedClient;
use Waffle\Commons\Auth\Credential\ApiKeyCredentialsProvider;
use Waffle\Commons\Auth\Credential\BearerCredentialsProvider;
use Waffle\Commons\Contracts\Auth\Constant;
use WaffleTests\Commons\Auth\AbstractTestCase;
use WaffleTests\Commons\Auth\Helper\FakeHttpClient;
use WaffleTests\Commons\Auth\Helper\FakeRequest;
use WaffleTests\Commons\Auth\Helper\FakeUri;

#[CoversClass(AuthenticatedClient::class)]
#[CoversClass(BearerCredentialsProvider::class)]
#[CoversClass(ApiKeyCredentialsProvider::class)]
final class AuthenticatedClientTest extends AbstractTestCase
{
    public function testAppliesEverySupportingProviderInOrder(): void
    {
        $transport = new FakeHttpClient();
        $client = new AuthenticatedClient($transport, [
            new BearerCredentialsProvider('the-token', ['api.example.test']),
            new ApiKeyCredentialsProvider('the-key', ['api.example.test']),
        ]);

        $client->sendRequest(new FakeRequest(uri: new FakeUri(host: 'api.example.test')));

        $sent = self::sent($transport);
        self::assertSame('Bearer the-token', $sent->getHeaderLine(Constant::AUTHORIZATION_HEADER));
        self::assertSame('the-key', $sent->getHeaderLine(Constant::API_KEY_HEADER));
    }

    public function testHostGatingPreventsCredentialLeakage(): void
    {
        $transport = new FakeHttpClient();
        $client = new AuthenticatedClient($transport, [
            new BearerCredentialsProvider('the-token', ['api.example.test']),
        ]);

        $client->sendRequest(new FakeRequest(uri: new FakeUri(host: 'evil.example.test')));

        self::assertFalse(self::sent($transport)->hasHeader(Constant::AUTHORIZATION_HEADER));
    }

    public function testNeverOverwritesAnExistingHeader(): void
    {
        $transport = new FakeHttpClient();
        $client = new AuthenticatedClient($transport, [
            new BearerCredentialsProvider('injected', ['api.example.test']),
        ]);

        $client->sendRequest(new FakeRequest(uri: new FakeUri(host: 'api.example.test'), headers: [
            Constant::AUTHORIZATION_HEADER => 'Bearer caller-supplied',
        ]));

        self::assertSame(
            'Bearer caller-supplied',
            self::sent($transport)->getHeaderLine(Constant::AUTHORIZATION_HEADER),
        );
    }
}
