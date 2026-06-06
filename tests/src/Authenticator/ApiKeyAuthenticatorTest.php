<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Authenticator;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Authenticator\ApiKeyAuthenticator;
use Waffle\Commons\Auth\Exception\AuthenticationException;
use Waffle\Commons\Auth\Identity\UserIdentity;
use Waffle\Commons\Contracts\Auth\Constant;
use WaffleTests\Commons\Auth\AbstractTestCase;
use WaffleTests\Commons\Auth\Helper\FakeServerRequest;

#[CoversClass(ApiKeyAuthenticator::class)]
final class ApiKeyAuthenticatorTest extends AbstractTestCase
{
    public function testSupportsOnlyWhenTheHeaderIsPresent(): void
    {
        $authenticator = new ApiKeyAuthenticator(['k' => new UserIdentity(subject: 'svc')]);

        self::assertTrue($authenticator->supports(new FakeServerRequest(headers: [Constant::API_KEY_HEADER => 'k'])));
        self::assertFalse($authenticator->supports(new FakeServerRequest()));
    }

    public function testAuthenticatesAConfiguredKey(): void
    {
        $identity = new UserIdentity(subject: 'svc-reporting', roles: ['ROLE_SERVICE']);
        $authenticator = new ApiKeyAuthenticator(['valid-key-123' => $identity]);

        $request = new FakeServerRequest(headers: [Constant::API_KEY_HEADER => 'valid-key-123']);

        self::assertSame($identity, $authenticator->authenticate($request));
    }

    public function testRejectsUnknownKeys(): void
    {
        $authenticator = new ApiKeyAuthenticator(['valid-key-123' => new UserIdentity(subject: 'svc')]);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionCode(401);

        $authenticator->authenticate(new FakeServerRequest(headers: [Constant::API_KEY_HEADER => 'wrong-key']));
    }

    public function testHonoursACustomHeaderName(): void
    {
        $identity = new UserIdentity(subject: 'svc');
        $authenticator = new ApiKeyAuthenticator(['k' => $identity], headerName: 'X-Custom-Key');

        self::assertTrue($authenticator->supports(new FakeServerRequest(headers: ['X-Custom-Key' => 'k'])));
        self::assertSame($identity, $authenticator->authenticate(new FakeServerRequest(headers: [
            'X-Custom-Key' => 'k',
        ])));
    }
}
