<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\WebAuthn;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Waffle\Commons\Auth\WebAuthn\AssertionOptions;
use Waffle\Commons\Auth\WebAuthn\Exception\InvalidWebAuthnAssertionException;
use Waffle\Commons\Auth\WebAuthn\Exception\InvalidWebAuthnRegistrationException;
use Waffle\Commons\Auth\WebAuthn\Exception\WebAuthnException;
use Waffle\Commons\Auth\WebAuthn\OptionsCodec;
use Waffle\Commons\Auth\WebAuthn\RegisteredCredential;
use Waffle\Commons\Auth\WebAuthn\RegistrationOptions;
use Waffle\Commons\Auth\WebAuthn\WebAuthnUser;
use Waffle\Commons\Contracts\Auth\Exception\AuthenticationExceptionInterface;
use Waffle\Commons\Contracts\Auth\Exception\AuthExceptionInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\Exception\InvalidWebAuthnAssertionExceptionInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\Exception\InvalidWebAuthnRegistrationExceptionInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\Exception\WebAuthnExceptionInterface;

#[CoversClass(WebAuthnUser::class)]
#[CoversClass(RegisteredCredential::class)]
#[CoversClass(RegistrationOptions::class)]
#[CoversClass(AssertionOptions::class)]
#[CoversClass(OptionsCodec::class)]
#[CoversClass(WebAuthnException::class)]
#[CoversClass(InvalidWebAuthnRegistrationException::class)]
#[CoversClass(InvalidWebAuthnAssertionException::class)]
final class WebAuthnValueObjectsTest extends TestCase
{
    public function testWebAuthnUserExposesItsFields(): void
    {
        $user = new WebAuthnUser('handle-1', 'login', 'Display Name');

        self::assertSame('handle-1', $user->id());
        self::assertSame('login', $user->name());
        self::assertSame('Display Name', $user->displayName());
    }

    public function testRegisteredCredentialExposesItsFields(): void
    {
        $credential = new RegisteredCredential('cred-id', 'pub-key', 'handle', 7, ['usb', 'nfc']);

        self::assertSame('cred-id', $credential->credentialId());
        self::assertSame('pub-key', $credential->publicKey());
        self::assertSame('handle', $credential->userHandle());
        self::assertSame(7, $credential->signCount());
        self::assertSame(['usb', 'nfc'], $credential->transports());
    }

    public function testRegisteredCredentialDefaultsToNoTransports(): void
    {
        self::assertSame([], new RegisteredCredential('id', 'key', 'handle', 0)->transports());
    }

    public function testRegistrationOptionsRoundTripJsonAndChallenge(): void
    {
        $options = new RegistrationOptions('chal-123', '{"challenge":"chal-123","rp":{"id":"x"}}');

        self::assertSame('chal-123', $options->challenge());
        self::assertSame('chal-123', $options->challenge);
        self::assertSame('{"challenge":"chal-123","rp":{"id":"x"}}', $options->json);
        self::assertSame('{"challenge":"chal-123","rp":{"id":"x"}}', $options->toJson());
        self::assertSame('chal-123', $options->toArray()['challenge'] ?? null);
    }

    public function testAssertionOptionsRoundTripJsonAndChallenge(): void
    {
        $options = new AssertionOptions('chal-abc', '{"challenge":"chal-abc"}');

        self::assertSame('chal-abc', $options->challenge());
        self::assertSame('chal-abc', $options->challenge);
        self::assertSame('{"challenge":"chal-abc"}', $options->json);
        self::assertSame('{"challenge":"chal-abc"}', $options->toJson());
        self::assertSame('chal-abc', $options->toArray()['challenge'] ?? null);
    }

    public function testRegistrationOptionsRejectAnEmptyChallenge(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new RegistrationOptions('', '{"x":1}');
    }

    public function testRegistrationOptionsRejectEmptyJson(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new RegistrationOptions('chal', '');
    }

    public function testAssertionOptionsRejectAnEmptyChallenge(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new AssertionOptions('', '{"x":1}');
    }

    public function testAssertionOptionsRejectEmptyJson(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new AssertionOptions('chal', '');
    }

    public function testOptionsCodecDecodesAJsonObject(): void
    {
        self::assertSame(['a' => 1, 'b' => 'two'], OptionsCodec::decode('{"a":1,"b":"two"}'));
    }

    public function testOptionsCodecRejectsMalformedJson(): void
    {
        $this->expectException(WebAuthnException::class);

        OptionsCodec::decode('{not-json');
    }

    public function testOptionsCodecRejectsANonObjectPayload(): void
    {
        $this->expectException(WebAuthnException::class);

        OptionsCodec::decode('"a string"');
    }

    public function testExceptionHierarchyAndHttpStatuses(): void
    {
        $registration = new InvalidWebAuthnRegistrationException('nope');
        $assertion = new InvalidWebAuthnAssertionException('nope');
        $base = new WebAuthnException('boom');

        self::assertInstanceOf(WebAuthnExceptionInterface::class, $base);
        self::assertInstanceOf(AuthExceptionInterface::class, $base);

        self::assertInstanceOf(InvalidWebAuthnRegistrationExceptionInterface::class, $registration);
        self::assertSame(400, $registration->getCode());

        self::assertInstanceOf(InvalidWebAuthnAssertionExceptionInterface::class, $assertion);
        self::assertInstanceOf(AuthenticationExceptionInterface::class, $assertion);
        self::assertSame(401, $assertion->getCode());
    }
}
