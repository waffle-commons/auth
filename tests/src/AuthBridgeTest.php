<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Client\AuthenticatedClient;
use Waffle\Commons\Auth\Credential\AssertionCredentialsProvider;
use Waffle\Commons\Auth\Exception\ClientIpHijackingException;
use Waffle\Commons\Auth\Exception\ExpiredAssertionException;
use Waffle\Commons\Auth\Exception\MissingAuthSecretException;
use Waffle\Commons\Auth\Exception\SignatureVerificationException;
use Waffle\Commons\Auth\Identity\UserIdentity;
use Waffle\Commons\Auth\Middleware\GatewayAssertionMiddleware;
use Waffle\Commons\Auth\SecurityContext;
use Waffle\Commons\Auth\Uab\AuthBridgeSigner;
use Waffle\Commons\Auth\Uab\AuthBridgeVerifier;
use Waffle\Commons\Auth\Uab\UserAssertion;
use Waffle\Commons\Contracts\Auth\Constant;
use Waffle\Commons\Contracts\Auth\UserIdentityInterface;
use WaffleTests\Commons\Auth\Helper\FakeHttpClient;
use WaffleTests\Commons\Auth\Helper\FakeRequest;
use WaffleTests\Commons\Auth\Helper\FakeServerRequest;
use WaffleTests\Commons\Auth\Helper\FakeUri;
use WaffleTests\Commons\Auth\Helper\PassHandler;

/**
 * RFC-021 §6 acceptance suite for the Gateway Assertion Protocol: generation,
 * outbound propagation, downstream interception, anti-replay, anti-hijacking,
 * tamper rejection, and fail-closed bootstrapping.
 */
#[CoversClass(AuthBridgeSigner::class)]
#[CoversClass(AuthBridgeVerifier::class)]
#[CoversClass(UserAssertion::class)]
#[CoversClass(AssertionCredentialsProvider::class)]
#[CoversClass(AuthenticatedClient::class)]
#[CoversClass(GatewayAssertionMiddleware::class)]
#[CoversClass(SecurityContext::class)]
final class AuthBridgeTest extends AbstractTestCase
{
    private static function sharedSecret(): string
    {
        return str_repeat('waffle-uab*', 4);
    }

    private const string CLIENT_IP = '203.0.113.7';

    public function testHappyPathPropagatesAndHydratesTheIdentityEndToEnd(): void
    {
        // --- Gateway side: an authenticated SecurityContext + asserted proxy call.
        $signer = new AuthBridgeSigner(self::sharedSecret());
        $gatewayContext = new SecurityContext();
        $gatewayContext->authenticate(
            new UserIdentity(subject: 'user-42', email: 'ada@example.test', roles: ['ROLE_ADMIN']),
            self::CLIENT_IP,
        );

        $transport = new FakeHttpClient();
        $client = new AuthenticatedClient($transport, [
            new AssertionCredentialsProvider($signer, $gatewayContext, ['legacy.test'], tenant: 'acme'),
        ]);

        $client->sendRequest(new FakeRequest(uri: new FakeUri(host: 'legacy.test')));

        $header = self::sent($transport)->getHeaderLine(Constant::ASSERTION_HEADER);
        self::assertNotSame('', $header, 'Outgoing proxied request must carry the signed assertion.');

        // --- Downstream side: the middleware verifies and boots a virtual session.
        $downstreamContext = new SecurityContext();
        $middleware = new GatewayAssertionMiddleware(new AuthBridgeVerifier(self::sharedSecret()), $downstreamContext);

        $handler = new PassHandler();
        $request = new FakeServerRequest(headers: [Constant::ASSERTION_HEADER => $header], serverParams: [
            'REMOTE_ADDR' => self::CLIENT_IP,
        ]);

        $middleware->process($request, $handler);

        self::assertTrue($downstreamContext->isAuthenticated());
        $identity = $downstreamContext->getIdentity();
        self::assertInstanceOf(UserIdentityInterface::class, $identity);
        self::assertSame('user-42', $identity->subject);
        self::assertSame('ada@example.test', $identity->email);
        self::assertSame(['ROLE_ADMIN'], $identity->roles);
        self::assertSame('acme', $identity->claims[Constant::CLAIM_TENANT] ?? null);

        self::assertNotNull($handler->received);
        self::assertSame($identity, self::received($handler)->getAttribute(Constant::REQUEST_ATTRIBUTE));
    }

    public function testAnonymousContextEmitsNoAssertionHeader(): void
    {
        $transport = new FakeHttpClient();
        $client = new AuthenticatedClient($transport, [
            new AssertionCredentialsProvider(
                new AuthBridgeSigner(self::sharedSecret()),
                new SecurityContext(),
                [
                    'legacy.test',
                ],
            ),
        ]);

        $client->sendRequest(new FakeRequest(uri: new FakeUri(host: 'legacy.test')));

        self::assertFalse(self::sent($transport)->hasHeader(Constant::ASSERTION_HEADER));
    }

    public function testACallerSuppliedAssertionHeaderIsNeverOverwritten(): void
    {
        $context = new SecurityContext();
        $context->authenticate(new UserIdentity(subject: 'user-42'), self::CLIENT_IP);

        $transport = new FakeHttpClient();
        $client = new AuthenticatedClient($transport, [
            new AssertionCredentialsProvider(new AuthBridgeSigner(self::sharedSecret()), $context, ['legacy.test']),
        ]);

        $client->sendRequest(new FakeRequest(uri: new FakeUri(host: 'legacy.test'), headers: [
            Constant::ASSERTION_HEADER => 'caller.supplied',
        ]));

        self::assertSame('caller.supplied', self::sent($transport)->getHeaderLine(Constant::ASSERTION_HEADER));
    }

    public function testIdentityWithoutARecordedClientIpEmitsNoHeader(): void
    {
        $context = new SecurityContext();
        $context->authenticate(new UserIdentity(subject: 'user-42'));

        $transport = new FakeHttpClient();
        $client = new AuthenticatedClient($transport, [
            new AssertionCredentialsProvider(new AuthBridgeSigner(self::sharedSecret()), $context, ['legacy.test']),
        ]);

        $client->sendRequest(new FakeRequest(uri: new FakeUri(host: 'legacy.test')));

        self::assertFalse(
            self::sent($transport)->hasHeader(Constant::ASSERTION_HEADER),
            'No IP binding possible without the original client IP — fail-closed, no header.',
        );
    }

    public function testReplayOlderThanFiveSecondsIsRejected(): void
    {
        $signer = new AuthBridgeSigner(self::sharedSecret());
        $stale = new UserAssertion(
            subject: 'user-42',
            email: null,
            roles: [],
            tenant: null,
            issuedAt: time() - 10,
            expiresAt: time() - 5,
            ipHash: $signer->hashClientIp(self::CLIENT_IP),
        );

        $this->expectException(ExpiredAssertionException::class);

        new AuthBridgeVerifier(self::sharedSecret())->verify($signer->sign($stale), self::CLIENT_IP);
    }

    public function testMismatchedClientIpTriggersHijackingRejection(): void
    {
        $signer = new AuthBridgeSigner(self::sharedSecret());
        $assertion = $this->freshAssertion($signer);

        $this->expectException(ClientIpHijackingException::class);

        new AuthBridgeVerifier(self::sharedSecret())->verify($signer->sign($assertion), '198.51.100.99');
    }

    public function testSingleCharacterTamperingTriggersSignatureRejection(): void
    {
        $signer = new AuthBridgeSigner(self::sharedSecret());
        $token = $signer->sign($this->freshAssertion($signer));

        // Flip exactly one character of the encoded payload.
        $tampered = ($token[0] === 'A' ? 'B' : 'A') . substr($token, 1);

        $this->expectException(SignatureVerificationException::class);

        new AuthBridgeVerifier(self::sharedSecret())->verify($tampered, self::CLIENT_IP);
    }

    public function testMissingSecretAbortsTheSignerBoot(): void
    {
        $this->expectException(MissingAuthSecretException::class);
        $this->expectExceptionMessage('WAFFLE_AUTH_SECRET');

        new AuthBridgeSigner('');
    }

    public function testWeakSecretAbortsTheVerifierBoot(): void
    {
        $this->expectException(MissingAuthSecretException::class);

        new AuthBridgeVerifier('too-short');
    }

    private function freshAssertion(AuthBridgeSigner $signer): UserAssertion
    {
        $now = time();

        return new UserAssertion(
            subject: 'user-42',
            email: 'ada@example.test',
            roles: ['ROLE_ADMIN'],
            tenant: 'acme',
            issuedAt: $now,
            expiresAt: $now + Constant::ASSERTION_TTL,
            ipHash: $signer->hashClientIp(self::CLIENT_IP),
        );
    }
}
