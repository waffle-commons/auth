<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Uab;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Codec\Base64Url;
use Waffle\Commons\Auth\Exception\ExpiredAssertionException;
use Waffle\Commons\Auth\Exception\InvalidAssertionException;
use Waffle\Commons\Auth\Exception\SignatureVerificationException;
use Waffle\Commons\Auth\Uab\AuthBridgeSigner;
use Waffle\Commons\Auth\Uab\AuthBridgeVerifier;
use Waffle\Commons\Auth\Uab\UserAssertion;
use Waffle\Commons\Contracts\Auth\Constant;
use WaffleTests\Commons\Auth\AbstractTestCase;

#[CoversClass(AuthBridgeVerifier::class)]
#[CoversClass(AuthBridgeSigner::class)]
final class AuthBridgeVerifierTest extends AbstractTestCase
{
    private static function sharedSecret(): string
    {
        return str_repeat('waffle-uab*', 4);
    }

    private const string CLIENT_IP = '203.0.113.7';

    public function testRoundTripReturnsTheAssertedClaims(): void
    {
        $signer = new AuthBridgeSigner(self::sharedSecret());
        $now = time();
        $token = $signer->sign(new UserAssertion(
            subject: 'user-42',
            email: 'ada@example.test',
            roles: ['ROLE_ADMIN', 'ROLE_AUDITOR'],
            tenant: 'acme',
            issuedAt: $now,
            expiresAt: $now + Constant::ASSERTION_TTL,
            ipHash: $signer->hashClientIp(self::CLIENT_IP),
        ));

        $assertion = new AuthBridgeVerifier(self::sharedSecret())->verify($token, self::CLIENT_IP);

        self::assertSame('user-42', $assertion->subject);
        self::assertSame('ada@example.test', $assertion->email);
        self::assertSame(['ROLE_ADMIN', 'ROLE_AUDITOR'], $assertion->roles);
        self::assertSame('acme', $assertion->tenant);
        self::assertSame($now, $assertion->issuedAt);
    }

    public function testStructurallyInvalidHeaderIsRejected(): void
    {
        $this->expectException(InvalidAssertionException::class);
        new AuthBridgeVerifier(self::sharedSecret())->verify('no-separator-here', self::CLIENT_IP);
    }

    public function testEmptySegmentsAreRejected(): void
    {
        $this->expectException(InvalidAssertionException::class);
        new AuthBridgeVerifier(self::sharedSecret())->verify('.', self::CLIENT_IP);
    }

    public function testForeignSecretSignatureIsRejected(): void
    {
        $foreign = new AuthBridgeSigner('a-completely-different-32-byte-secret-value!');
        $now = time();
        $token = $foreign->sign(new UserAssertion(
            subject: 'user-42',
            email: null,
            roles: [],
            tenant: null,
            issuedAt: $now,
            expiresAt: $now + 5,
            ipHash: $foreign->hashClientIp(self::CLIENT_IP),
        ));

        $this->expectException(SignatureVerificationException::class);
        new AuthBridgeVerifier(self::sharedSecret())->verify($token, self::CLIENT_IP);
    }

    public function testFutureIssuedAtIsRejected(): void
    {
        $token = $this->signRaw([
            Constant::CLAIM_SUBJECT => 'user-42',
            Constant::CLAIM_EMAIL => null,
            Constant::CLAIM_ROLES => [],
            Constant::CLAIM_TENANT => null,
            Constant::CLAIM_ISSUED_AT => time() + 60,
            Constant::CLAIM_EXPIRES_AT => time() + 63,
            Constant::CLAIM_IP_HASH => new AuthBridgeSigner(self::sharedSecret())->hashClientIp(self::CLIENT_IP),
        ]);

        $this->expectException(ExpiredAssertionException::class);
        new AuthBridgeVerifier(self::sharedSecret())->verify($token, self::CLIENT_IP);
    }

    public function testWindowWideningBeyondTheTtlIsRejected(): void
    {
        $token = $this->signRaw([
            Constant::CLAIM_SUBJECT => 'user-42',
            Constant::CLAIM_EMAIL => null,
            Constant::CLAIM_ROLES => [],
            Constant::CLAIM_TENANT => null,
            Constant::CLAIM_ISSUED_AT => time() - 60,
            Constant::CLAIM_EXPIRES_AT => time() + 3_600,
            Constant::CLAIM_IP_HASH => new AuthBridgeSigner(self::sharedSecret())->hashClientIp(self::CLIENT_IP),
        ]);

        $this->expectException(InvalidAssertionException::class);
        new AuthBridgeVerifier(self::sharedSecret())->verify($token, self::CLIENT_IP);
    }

    public function testMistypedClaimsAreRejected(): void
    {
        $token = $this->signRaw([
            Constant::CLAIM_SUBJECT => 42,
            Constant::CLAIM_ISSUED_AT => 'not-an-int',
        ]);

        $this->expectException(InvalidAssertionException::class);
        new AuthBridgeVerifier(self::sharedSecret())->verify($token, self::CLIENT_IP);
    }

    public function testMistypedEmailClaimIsRejected(): void
    {
        $token = $this->signRaw([
            Constant::CLAIM_SUBJECT => 'user-42',
            Constant::CLAIM_EMAIL => 42,
            Constant::CLAIM_ROLES => [],
            Constant::CLAIM_TENANT => null,
            Constant::CLAIM_ISSUED_AT => time(),
            Constant::CLAIM_EXPIRES_AT => time() + 5,
            Constant::CLAIM_IP_HASH => new AuthBridgeSigner(self::sharedSecret())->hashClientIp(self::CLIENT_IP),
        ]);

        $this->expectException(InvalidAssertionException::class);
        new AuthBridgeVerifier(self::sharedSecret())->verify($token, self::CLIENT_IP);
    }

    public function testNonJsonPayloadIsRejected(): void
    {
        $encoded = Base64Url::encode('this is not json');
        $signature = hash_hmac('sha256', $encoded, self::sharedSecret());

        $this->expectException(InvalidAssertionException::class);
        new AuthBridgeVerifier(self::sharedSecret())->verify($encoded . '.' . $signature, self::CLIENT_IP);
    }

    public function testValidlySignedNonBase64PayloadIsRejected(): void
    {
        // '!!!' is not base64url, but the MAC over it is valid — the verifier
        // must still reject at the decoding stage.
        $token = '!!!.' . hash_hmac('sha256', '!!!', self::sharedSecret());

        $this->expectException(InvalidAssertionException::class);
        $this->expectExceptionMessage('base64url');

        new AuthBridgeVerifier(self::sharedSecret())->verify($token, self::CLIENT_IP);
    }

    public function testNonObjectJsonPayloadIsRejected(): void
    {
        $encoded = Base64Url::encode('"just-a-string"');
        $signature = hash_hmac('sha256', $encoded, self::sharedSecret());

        $this->expectException(InvalidAssertionException::class);
        new AuthBridgeVerifier(self::sharedSecret())->verify($encoded . '.' . $signature, self::CLIENT_IP);
    }

    public function testNonStringRolesAreRejected(): void
    {
        $token = $this->signRaw([
            Constant::CLAIM_SUBJECT => 'user-42',
            Constant::CLAIM_EMAIL => null,
            Constant::CLAIM_ROLES => [1, 2],
            Constant::CLAIM_TENANT => null,
            Constant::CLAIM_ISSUED_AT => time(),
            Constant::CLAIM_EXPIRES_AT => time() + 5,
            Constant::CLAIM_IP_HASH => new AuthBridgeSigner(self::sharedSecret())->hashClientIp(self::CLIENT_IP),
        ]);

        $this->expectException(InvalidAssertionException::class);
        new AuthBridgeVerifier(self::sharedSecret())->verify($token, self::CLIENT_IP);
    }

    /**
     * Signs an arbitrary (possibly schema-violating) payload — what a buggy
     * or malicious sender holding the shared secret could emit.
     *
     * @param array<string, mixed> $claims
     */
    private function signRaw(array $claims): string
    {
        $encoded = Base64Url::encode(json_encode($claims, flags: JSON_THROW_ON_ERROR));

        return $encoded . '.' . hash_hmac('sha256', $encoded, self::sharedSecret());
    }
}
