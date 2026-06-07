<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\AuthenticationBridge;
use Waffle\Commons\Auth\Authenticator\ApiKeyAuthenticator;
use Waffle\Commons\Auth\Authenticator\BasicAuthenticator;
use Waffle\Commons\Auth\Exception\AuthenticationException;
use Waffle\Commons\Auth\Identity\UserIdentity;
use Waffle\Commons\Auth\SecurityContext;
use Waffle\Commons\Contracts\Auth\Constant;
use WaffleTests\Commons\Auth\Helper\FakeServerRequest;

#[CoversClass(AuthenticationBridge::class)]
final class AuthenticationBridgeTest extends AbstractTestCase
{
    public function testFirstSupportingSchemeWinsAndPopulatesTheContext(): void
    {
        $identity = new UserIdentity(subject: 'svc-api');
        $context = new SecurityContext();
        $bridge = new AuthenticationBridge($context, [
            new ApiKeyAuthenticator(['the-key' => $identity]),
            new BasicAuthenticator(['ada' => 'secret']),
        ]);

        $request = new FakeServerRequest(headers: [Constant::API_KEY_HEADER => 'the-key'], serverParams: [
            'REMOTE_ADDR' => '203.0.113.7',
        ]);

        self::assertSame($identity, $bridge->authenticate($request));
        self::assertSame($identity, $context->getIdentity());
        self::assertSame('203.0.113.7', $context->getClientIp());
    }

    public function testAnonymousRequestsReturnNullWithoutTouchingTheContext(): void
    {
        $context = new SecurityContext();
        $bridge = new AuthenticationBridge($context, [
            new ApiKeyAuthenticator(['the-key' => new UserIdentity(subject: 'svc')]),
        ]);

        self::assertNull($bridge->authenticate(new FakeServerRequest()));
        self::assertFalse($context->isAuthenticated());
    }

    public function testRejectionPropagatesWithoutFallbackToLaterSchemes(): void
    {
        $context = new SecurityContext();
        $bridge = new AuthenticationBridge($context, [
            new ApiKeyAuthenticator(['the-key' => new UserIdentity(subject: 'svc')]),
            // A Basic authenticator that WOULD accept — must never be reached.
            new BasicAuthenticator(['ada' => 'secret']),
        ]);

        $request = new FakeServerRequest(headers: [
            Constant::API_KEY_HEADER => 'wrong-key',
            Constant::AUTHORIZATION_HEADER => Constant::BASIC_PREFIX . base64_encode('ada:secret'),
        ]);

        $this->expectException(AuthenticationException::class);

        try {
            $bridge->authenticate($request);
        } finally {
            self::assertFalse($context->isAuthenticated(), 'Fail-closed: no identity after a rejection.');
        }
    }
}
