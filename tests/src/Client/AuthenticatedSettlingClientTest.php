<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Client;

use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Http\Message\RequestInterface;
use Waffle\Commons\Auth\Client\AuthenticatedSettlingClient;
use Waffle\Commons\Auth\Client\Credentials;
use Waffle\Commons\Auth\Credential\BearerCredentialsProvider;
use Waffle\Commons\Contracts\Auth\Constant;
use Waffle\Commons\Contracts\HttpClient\PromiseInterface;
use WaffleTests\Commons\Auth\AbstractTestCase;
use WaffleTests\Commons\Auth\Helper\FakeRequest;
use WaffleTests\Commons\Auth\Helper\FakeSettlingClient;
use WaffleTests\Commons\Auth\Helper\FakeUri;

#[CoversClass(AuthenticatedSettlingClient::class)]
#[CoversClass(Credentials::class)]
#[CoversClass(BearerCredentialsProvider::class)]
final class AuthenticatedSettlingClientTest extends AbstractTestCase
{
    public function testABatchStaysOneBatchAndEachRequestGetsItsOwnCredentials(): void
    {
        $transport = new FakeSettlingClient();

        $outcomes = self::client($transport)
            ->settleRequests([
                'api' => self::request('api.example.test'),
                'evil' => self::request('evil.example.test'),
            ]);

        self::assertSame(['api', 'evil'], array_keys($outcomes));
        self::assertSame([['api', 'evil']], $transport->batches);
        self::assertSame(
            'Bearer the-token',
            self::sentAt($transport, 0)->getHeaderLine(Constant::AUTHORIZATION_HEADER),
        );
        self::assertFalse(self::sentAt($transport, 1)->hasHeader(Constant::AUTHORIZATION_HEADER));
    }

    public function testTheFailFastBatchGoesThroughTheInnerBatch(): void
    {
        $transport = new FakeSettlingClient();

        $responses = self::client($transport)->sendRequests([7 => self::request('api.example.test')]);

        self::assertSame([7], array_keys($responses));
        self::assertSame([[7]], $transport->batches);
        self::assertTrue(self::sentAt($transport, 0)->hasHeader(Constant::AUTHORIZATION_HEADER));
    }

    public function testASingleRequestCarriesItsCredentials(): void
    {
        $transport = new FakeSettlingClient();

        self::client($transport)->sendRequest(self::request('api.example.test'));

        self::assertSame([], $transport->batches);
        self::assertSame(
            'Bearer the-token',
            self::sentAt($transport, 0)->getHeaderLine(Constant::AUTHORIZATION_HEADER),
        );
    }

    public function testAPromiseIsTheInnerPromiseOfTheAuthenticatedRequest(): void
    {
        $promise = $this->createStub(PromiseInterface::class);
        $transport = new FakeSettlingClient($promise);

        self::assertSame($promise, self::client($transport)->promise(self::request('api.example.test')));
        self::assertTrue(self::sentAt($transport, 0)->hasHeader(Constant::AUTHORIZATION_HEADER));
    }

    private static function client(FakeSettlingClient $transport): AuthenticatedSettlingClient
    {
        return new AuthenticatedSettlingClient($transport, [
            new BearerCredentialsProvider('the-token', ['api.example.test']),
        ]);
    }

    private static function request(string $host): FakeRequest
    {
        return new FakeRequest(uri: new FakeUri(host: $host));
    }

    private static function sentAt(FakeSettlingClient $transport, int $index): RequestInterface
    {
        return $transport->sent[$index] ?? self::fail(sprintf('No request #%d reached the settling spy.', $index));
    }
}
