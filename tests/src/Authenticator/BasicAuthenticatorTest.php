<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Authenticator;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Authenticator\BasicAuthenticator;
use Waffle\Commons\Auth\Exception\AuthenticationException;
use Waffle\Commons\Contracts\Auth\Constant;
use WaffleTests\Commons\Auth\AbstractTestCase;
use WaffleTests\Commons\Auth\Helper\FakeServerRequest;

#[CoversClass(BasicAuthenticator::class)]
final class BasicAuthenticatorTest extends AbstractTestCase
{
    public function testSupportsOnlyBasicSchemeHeaders(): void
    {
        $authenticator = new BasicAuthenticator(['ada' => 'secret']);

        self::assertTrue($authenticator->supports(self::request('ada', 'secret')));
        self::assertFalse($authenticator->supports(new FakeServerRequest(headers: [
            Constant::AUTHORIZATION_HEADER => 'Bearer token',
        ])));
        self::assertFalse($authenticator->supports(new FakeServerRequest()));
    }

    public function testAuthenticatesHashedPasswordsViaPasswordVerify(): void
    {
        $authenticator = new BasicAuthenticator(['ada' => password_hash('s3cret', PASSWORD_BCRYPT)], roles: [
            'ROLE_USER',
        ]);

        $identity = $authenticator->authenticate(self::request('ada', 's3cret'));

        self::assertSame('ada', $identity->subject);
        self::assertSame(['ROLE_USER'], $identity->roles);
    }

    public function testAuthenticatesOpaqueTokensViaHashEquals(): void
    {
        $authenticator = new BasicAuthenticator(['svc' => 'opaque-shared-token']);

        self::assertSame('svc', $authenticator->authenticate(self::request('svc', 'opaque-shared-token'))->subject);
    }

    public function testRejectsWrongPassword(): void
    {
        $authenticator = new BasicAuthenticator(['ada' => password_hash('s3cret', PASSWORD_BCRYPT)]);

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate(self::request('ada', 'wrong'));
    }

    public function testRejectsUnknownUser(): void
    {
        $authenticator = new BasicAuthenticator(['ada' => 'secret']);

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate(self::request('eve', 'secret'));
    }

    public function testRejectsMalformedBase64(): void
    {
        $authenticator = new BasicAuthenticator(['ada' => 'secret']);
        $request = new FakeServerRequest(headers: [Constant::AUTHORIZATION_HEADER => 'Basic !!!not-base64!!!']);

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($request);
    }

    public function testRejectsCredentialsWithoutSeparator(): void
    {
        $authenticator = new BasicAuthenticator(['ada' => 'secret']);
        $request = new FakeServerRequest(headers: [
            Constant::AUTHORIZATION_HEADER => Constant::BASIC_PREFIX . base64_encode('no-separator'),
        ]);

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($request);
    }

    public function testRejectsEmptyUsernameAs401(): void
    {
        $authenticator = new BasicAuthenticator(['' => 'secret']);

        $this->expectException(AuthenticationException::class);
        $this->expectExceptionCode(401);

        $authenticator->authenticate(self::request('', 'secret'));
    }

    private static function request(string $user, #[\SensitiveParameter] string $password): FakeServerRequest
    {
        return new FakeServerRequest(headers: [
            Constant::AUTHORIZATION_HEADER => Constant::BASIC_PREFIX . base64_encode($user . ':' . $password),
        ]);
    }
}
