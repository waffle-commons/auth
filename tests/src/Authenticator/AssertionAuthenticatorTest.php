<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Authenticator;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Authenticator\AssertionAuthenticator;
use Waffle\Commons\Auth\Exception\ClientIpHijackingException;
use Waffle\Commons\Auth\Uab\AuthBridgeSigner;
use Waffle\Commons\Auth\Uab\AuthBridgeVerifier;
use Waffle\Commons\Auth\Uab\UserAssertion;
use Waffle\Commons\Contracts\Auth\Constant;
use WaffleTests\Commons\Auth\AbstractTestCase;
use WaffleTests\Commons\Auth\Helper\FakeServerRequest;

#[CoversClass(AssertionAuthenticator::class)]
final class AssertionAuthenticatorTest extends AbstractTestCase
{
    private static function sharedSecret(): string
    {
        return str_repeat('waffle-uab*', 4);
    }

    private const string CLIENT_IP = '203.0.113.7';

    public function testSupportsOnlyWhenTheAssertionHeaderIsPresent(): void
    {
        $authenticator = new AssertionAuthenticator(new AuthBridgeVerifier(self::sharedSecret()));

        self::assertTrue($authenticator->supports(new FakeServerRequest(headers: [
            Constant::ASSERTION_HEADER => 'x.y',
        ])));
        self::assertFalse($authenticator->supports(new FakeServerRequest()));
    }

    public function testAuthenticatesAVerifiedAssertionAgainstTheRemoteAddress(): void
    {
        $authenticator = new AssertionAuthenticator(new AuthBridgeVerifier(self::sharedSecret()));
        $request = new FakeServerRequest(headers: [Constant::ASSERTION_HEADER => $this->token()], serverParams: [
            'REMOTE_ADDR' => self::CLIENT_IP,
        ]);

        $identity = $authenticator->authenticate($request);

        self::assertSame('user-42', $identity->subject);
        self::assertSame('acme', $identity->claims[Constant::CLAIM_TENANT] ?? null);
    }

    public function testMissingRemoteAddressFailsIpBinding(): void
    {
        $authenticator = new AssertionAuthenticator(new AuthBridgeVerifier(self::sharedSecret()));
        $request = new FakeServerRequest(headers: [Constant::ASSERTION_HEADER => $this->token()]);

        $this->expectException(ClientIpHijackingException::class);

        $authenticator->authenticate($request);
    }

    private function token(): string
    {
        $signer = new AuthBridgeSigner(self::sharedSecret());
        $now = time();

        return $signer->sign(new UserAssertion(
            subject: 'user-42',
            email: null,
            roles: ['ROLE_ADMIN'],
            tenant: 'acme',
            issuedAt: $now,
            expiresAt: $now + Constant::ASSERTION_TTL,
            ipHash: $signer->hashClientIp(self::CLIENT_IP),
        ));
    }
}
