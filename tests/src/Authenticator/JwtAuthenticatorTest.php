<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Authenticator;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Authenticator\JwtAuthenticator;
use Waffle\Commons\Auth\Jwt\JwtConfig;
use Waffle\Commons\Auth\Jwt\JwtValidator;
use Waffle\Commons\Auth\Jwt\Key\StaticKeyResolver;
use Waffle\Commons\Contracts\Auth\Constant;
use WaffleTests\Commons\Auth\AbstractTestCase;
use WaffleTests\Commons\Auth\Helper\FakeServerRequest;
use WaffleTests\Commons\Auth\Helper\JwtMinter;

#[CoversClass(JwtAuthenticator::class)]
final class JwtAuthenticatorTest extends AbstractTestCase
{
    private static function sharedSecret(): string
    {
        return str_repeat('waffle-uab*', 4);
    }

    public function testSupportsOnlyBearerHeaders(): void
    {
        $authenticator = $this->authenticator();

        self::assertTrue($authenticator->supports(new FakeServerRequest(headers: [
            Constant::AUTHORIZATION_HEADER => 'Bearer abc',
        ])));
        self::assertFalse($authenticator->supports(new FakeServerRequest(headers: [
            Constant::AUTHORIZATION_HEADER => 'Basic abc',
        ])));
        self::assertFalse($authenticator->supports(new FakeServerRequest()));
    }

    public function testExtractsTheTokenAndDelegatesValidation(): void
    {
        $token = JwtMinter::hs256(self::sharedSecret(), [
            'sub' => 'user-42',
            'iss' => 'https://idp.example.test',
            'aud' => 'waffle-app',
            'exp' => time() + 60,
        ]);

        $identity = $this->authenticator()->authenticate(new FakeServerRequest(headers: [
            Constant::AUTHORIZATION_HEADER => Constant::BEARER_PREFIX . $token,
        ]));

        self::assertSame('user-42', $identity->subject);
    }

    private function authenticator(): JwtAuthenticator
    {
        return new JwtAuthenticator(new JwtValidator(
            config: new JwtConfig(algorithms: ['HS256'], issuer: 'https://idp.example.test', audience: 'waffle-app'),
            keys: new StaticKeyResolver(['HS256' => self::sharedSecret()]),
        ));
    }
}
