<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Middleware;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Exception\SignatureVerificationException;
use Waffle\Commons\Auth\Middleware\GatewayAssertionMiddleware;
use Waffle\Commons\Auth\SecurityContext;
use Waffle\Commons\Auth\Uab\AuthBridgeSigner;
use Waffle\Commons\Auth\Uab\AuthBridgeVerifier;
use Waffle\Commons\Auth\Uab\UserAssertion;
use Waffle\Commons\Contracts\Auth\Constant;
use WaffleTests\Commons\Auth\AbstractTestCase;
use WaffleTests\Commons\Auth\Helper\FakeServerRequest;
use WaffleTests\Commons\Auth\Helper\PassHandler;

#[CoversClass(GatewayAssertionMiddleware::class)]
final class GatewayAssertionMiddlewareTest extends AbstractTestCase
{
    private static function sharedSecret(): string
    {
        return str_repeat('waffle-uab*', 4);
    }

    private const string CLIENT_IP = '203.0.113.7';

    public function testAbsentHeaderMeansAnonymousPassThrough(): void
    {
        $context = new SecurityContext();
        $middleware = new GatewayAssertionMiddleware(new AuthBridgeVerifier(self::sharedSecret()), $context);
        $handler = new PassHandler();

        $middleware->process(new FakeServerRequest(), $handler);

        self::assertFalse($context->isAuthenticated());
        self::assertNotNull($handler->received);
        self::assertNull(self::received($handler)->getAttribute(Constant::REQUEST_ATTRIBUTE));
    }

    public function testValidAssertionBootsAVirtualSession(): void
    {
        $context = new SecurityContext();
        $middleware = new GatewayAssertionMiddleware(new AuthBridgeVerifier(self::sharedSecret()), $context);
        $handler = new PassHandler();

        $request = new FakeServerRequest(headers: [Constant::ASSERTION_HEADER => $this->token()], serverParams: [
            'REMOTE_ADDR' => self::CLIENT_IP,
        ]);

        $middleware->process($request, $handler);

        self::assertTrue($context->isAuthenticated());
        self::assertSame(self::CLIENT_IP, $context->getClientIp());
        self::assertNotNull($handler->received);
        self::assertNotNull(self::received($handler)->getAttribute(Constant::REQUEST_ATTRIBUTE));
    }

    public function testTamperedAssertionRejectsBeforeTheHandlerRuns(): void
    {
        $context = new SecurityContext();
        $middleware = new GatewayAssertionMiddleware(new AuthBridgeVerifier(self::sharedSecret()), $context);
        $handler = new PassHandler();

        $request = new FakeServerRequest(headers: [
            Constant::ASSERTION_HEADER => $this->token() . 'tamper',
        ], serverParams: ['REMOTE_ADDR' => self::CLIENT_IP]);

        try {
            $middleware->process($request, $handler);
            self::fail('A SignatureVerificationException was expected.');
        } catch (SignatureVerificationException $e) {
            self::assertSame(403, $e->getCode());
            self::assertNull($handler->received, 'Fail-closed: the business handler must never run.');
            self::assertFalse($context->isAuthenticated());
        }
    }

    private function token(): string
    {
        $signer = new AuthBridgeSigner(self::sharedSecret());
        $now = time();

        return $signer->sign(new UserAssertion(
            subject: 'user-42',
            email: null,
            roles: [],
            tenant: null,
            issuedAt: $now,
            expiresAt: $now + Constant::ASSERTION_TTL,
            ipHash: $signer->hashClientIp(self::CLIENT_IP),
        ));
    }
}
