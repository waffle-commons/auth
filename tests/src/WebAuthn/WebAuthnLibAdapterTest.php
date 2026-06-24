<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\WebAuthn;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Waffle\Commons\Auth\WebAuthn\AssertionOptions;
use Waffle\Commons\Auth\WebAuthn\Exception\InvalidWebAuthnAssertionException;
use Waffle\Commons\Auth\WebAuthn\Exception\InvalidWebAuthnRegistrationException;
use Waffle\Commons\Auth\WebAuthn\Exception\WebAuthnException;
use Waffle\Commons\Auth\WebAuthn\RegisteredCredential;
use Waffle\Commons\Auth\WebAuthn\RegistrationOptions;
use Waffle\Commons\Auth\WebAuthn\WebAuthnLibAdapter;
use Waffle\Commons\Auth\WebAuthn\WebAuthnUser;
use WaffleTests\Commons\Auth\WebAuthn\Helper\WebAuthnFixtureFactory;

#[CoversClass(WebAuthnLibAdapter::class)]
#[CoversClass(RegistrationOptions::class)]
#[CoversClass(AssertionOptions::class)]
#[CoversClass(RegisteredCredential::class)]
#[CoversClass(WebAuthnUser::class)]
final class WebAuthnLibAdapterTest extends TestCase
{
    private function adapter(): WebAuthnLibAdapter
    {
        return new WebAuthnLibAdapter(
            WebAuthnFixtureFactory::RP_ID,
            'Waffle Test RP',
            [WebAuthnFixtureFactory::ORIGIN],
        );
    }

    private function userVerifyingAdapter(): WebAuthnLibAdapter
    {
        return new WebAuthnLibAdapter(
            WebAuthnFixtureFactory::RP_ID,
            'Waffle Test RP',
            [WebAuthnFixtureFactory::ORIGIN],
            'required',
        );
    }

    private function user(): WebAuthnUser
    {
        return new WebAuthnUser(WebAuthnFixtureFactory::USER_HANDLE, 'alice', 'Alice Example');
    }

    public function testCreateRegistrationOptionsCarriesAChallengeAndJson(): void
    {
        $options = $this->adapter()->createRegistrationOptions($this->user());

        self::assertNotSame('', $options->challenge());
        $array = $options->toArray();
        self::assertSame($options->challenge(), $array['challenge'] ?? null);
        self::assertStringContainsString('"challenge"', $options->toJson());
    }

    public function testRegistrationOptionsExcludeAlreadyEnrolledCredentials(): void
    {
        $fixture = new WebAuthnFixtureFactory();
        $existing = new RegisteredCredential(
            credentialId: $fixture->credentialId(),
            publicKey: $fixture->publicKey(),
            userHandle: $fixture->userHandle(),
            signCount: 0,
            transports: ['internal'],
        );

        $options = $this->adapter()->createRegistrationOptions($this->user(), [$existing]);

        self::assertStringContainsString('excludeCredentials', $options->toJson());
    }

    public function testCreateRegistrationOptionsFailsOnACorruptedExistingCredential(): void
    {
        $corrupted = new RegisteredCredential('not valid base64url !!!', 'pk', 'handle', 0);

        $this->expectException(WebAuthnException::class);

        $this->adapter()->createRegistrationOptions($this->user(), [$corrupted]);
    }

    public function testCreateRegistrationOptionsFailsOnAnOversizedUserHandle(): void
    {
        // The library caps the user handle at 64 bytes; a longer handle makes it
        // throw, which the adapter wraps as a fail-closed WebAuthnException.
        $oversized = new WebAuthnUser(str_repeat('x', 65), 'alice', 'Alice');

        $this->expectException(WebAuthnException::class);

        $this->adapter()->createRegistrationOptions($oversized);
    }

    public function testCreateAssertionOptionsFailsOnACorruptedAllowedCredential(): void
    {
        $corrupted = new RegisteredCredential('not valid base64url !!!', 'pk', 'handle', 0);

        $this->expectException(WebAuthnException::class);

        $this->adapter()->createAssertionOptions([$corrupted]);
    }

    public function testVerifiesAGenuineAttestationResponse(): void
    {
        $adapter = $this->adapter();
        $fixture = new WebAuthnFixtureFactory();
        $options = $adapter->createRegistrationOptions($this->user());

        $credential = $adapter->verifyRegistration($options, $fixture->registrationResponseJson($options->challenge()));

        self::assertSame($fixture->credentialId(), $credential->credentialId());
        self::assertSame($fixture->publicKey(), $credential->publicKey());
        self::assertSame(0, $credential->signCount());
        self::assertContains('internal', $credential->transports());
    }

    public function testRejectsAttestationWithATamperedChallenge(): void
    {
        $adapter = $this->adapter();
        $fixture = new WebAuthnFixtureFactory();
        $options = $adapter->createRegistrationOptions($this->user());

        // Sign the client data against a different challenge than the issued one.
        $wrongChallenge = $adapter->createRegistrationOptions($this->user())->challenge();

        $this->expectException(InvalidWebAuthnRegistrationException::class);

        $adapter->verifyRegistration($options, $fixture->registrationResponseJson($wrongChallenge));
    }

    public function testRejectsAttestationFromAnUnexpectedOrigin(): void
    {
        $adapter = $this->adapter();
        $fixture = new WebAuthnFixtureFactory();
        $options = $adapter->createRegistrationOptions($this->user());

        $this->expectException(InvalidWebAuthnRegistrationException::class);

        $adapter->verifyRegistration($options, $fixture->registrationResponseJson(
            $options->challenge(),
            'https://evil.example.com',
        ));
    }

    public function testRejectsRegistrationWhenTheResponseIsNotAttestation(): void
    {
        $adapter = $this->adapter();
        $fixture = new WebAuthnFixtureFactory();
        $options = $adapter->createRegistrationOptions($this->user());

        $this->expectException(InvalidWebAuthnRegistrationException::class);

        // An assertion-shaped response cannot satisfy a registration ceremony.
        $adapter->verifyRegistration($options, $fixture->assertionResponseJson($options->challenge()));
    }

    public function testRejectsRegistrationWithMalformedJson(): void
    {
        $adapter = $this->adapter();
        $options = $adapter->createRegistrationOptions($this->user());

        $this->expectException(InvalidWebAuthnRegistrationException::class);

        $adapter->verifyRegistration($options, '{not-json');
    }

    public function testVerifiesAGenuineAssertionAndReturnsTheNewSignCount(): void
    {
        $adapter = $this->adapter();
        $fixture = new WebAuthnFixtureFactory();

        $registrationOptions = $adapter->createRegistrationOptions($this->user());
        $credential = $adapter->verifyRegistration(
            $registrationOptions,
            $fixture->registrationResponseJson($registrationOptions->challenge()),
        );

        $assertionOptions = $adapter->createAssertionOptions([$credential]);
        $newSignCount = $adapter->verifyAssertion(
            $assertionOptions,
            $fixture->assertionResponseJson($assertionOptions->challenge(), 9),
            $credential,
        );

        self::assertSame(9, $newSignCount);
    }

    public function testAssertionOptionsListAllowedCredentials(): void
    {
        $fixture = new WebAuthnFixtureFactory();
        $credential = new RegisteredCredential(
            credentialId: $fixture->credentialId(),
            publicKey: $fixture->publicKey(),
            userHandle: $fixture->userHandle(),
            signCount: 0,
        );

        $options = $this->adapter()->createAssertionOptions([$credential]);

        self::assertNotSame('', $options->challenge());
        self::assertStringContainsString('allowCredentials', $options->toJson());
        self::assertSame($options->challenge(), $options->toArray()['challenge'] ?? null);
    }

    public function testRejectsAssertionWithATamperedChallenge(): void
    {
        $adapter = $this->adapter();
        $fixture = new WebAuthnFixtureFactory();

        $registrationOptions = $adapter->createRegistrationOptions($this->user());
        $credential = $adapter->verifyRegistration(
            $registrationOptions,
            $fixture->registrationResponseJson($registrationOptions->challenge()),
        );

        $assertionOptions = $adapter->createAssertionOptions([$credential]);
        $otherChallenge = $adapter->createAssertionOptions([$credential])->challenge();

        $this->expectException(InvalidWebAuthnAssertionException::class);

        $adapter->verifyAssertion($assertionOptions, $fixture->assertionResponseJson($otherChallenge), $credential);
    }

    public function testRejectsAssertionFromAnUnexpectedOrigin(): void
    {
        $adapter = $this->adapter();
        $fixture = new WebAuthnFixtureFactory();

        $registrationOptions = $adapter->createRegistrationOptions($this->user());
        $credential = $adapter->verifyRegistration(
            $registrationOptions,
            $fixture->registrationResponseJson($registrationOptions->challenge()),
        );

        $assertionOptions = $adapter->createAssertionOptions([$credential]);

        $this->expectException(InvalidWebAuthnAssertionException::class);

        $adapter->verifyAssertion(
            $assertionOptions,
            $fixture->assertionResponseJson($assertionOptions->challenge(), 9, 'https://evil.example.com'),
            $credential,
        );
    }

    public function testRejectsAssertionWithARegressedSignCounter(): void
    {
        $adapter = $this->adapter();
        $fixture = new WebAuthnFixtureFactory();

        $registrationOptions = $adapter->createRegistrationOptions($this->user());
        $credential = $adapter->verifyRegistration(
            $registrationOptions,
            $fixture->registrationResponseJson($registrationOptions->challenge()),
        );

        // Stored credential has advanced to counter 10; a lower value signals a clone.
        $stored = new RegisteredCredential(
            credentialId: $credential->credentialId(),
            publicKey: $credential->publicKey(),
            userHandle: $credential->userHandle(),
            signCount: 10,
            transports: $credential->transports(),
        );

        $assertionOptions = $adapter->createAssertionOptions([$stored]);

        $this->expectException(InvalidWebAuthnAssertionException::class);

        $adapter->verifyAssertion(
            $assertionOptions,
            $fixture->regressedAssertionResponseJson($assertionOptions->challenge(), 10),
            $stored,
        );
    }

    public function testRejectsAssertionWhenTheResponseIsNotAssertion(): void
    {
        $adapter = $this->adapter();
        $fixture = new WebAuthnFixtureFactory();

        $registrationOptions = $adapter->createRegistrationOptions($this->user());
        $credential = $adapter->verifyRegistration(
            $registrationOptions,
            $fixture->registrationResponseJson($registrationOptions->challenge()),
        );

        $assertionOptions = $adapter->createAssertionOptions([$credential]);

        $this->expectException(InvalidWebAuthnAssertionException::class);

        // An attestation-shaped response cannot satisfy an assertion ceremony.
        $adapter->verifyAssertion(
            $assertionOptions,
            $fixture->registrationResponseJson($assertionOptions->challenge()),
            $credential,
        );
    }

    public function testRejectsAssertionWithMalformedJson(): void
    {
        $adapter = $this->adapter();
        $fixture = new WebAuthnFixtureFactory();
        $assertionOptions = $adapter->createAssertionOptions();
        $credential = new RegisteredCredential(
            credentialId: $fixture->credentialId(),
            publicKey: $fixture->publicKey(),
            userHandle: $fixture->userHandle(),
            signCount: 0,
        );

        $this->expectException(InvalidWebAuthnAssertionException::class);

        $adapter->verifyAssertion($assertionOptions, '{not-json', $credential);
    }

    public function testRejectsAssertionWithACorruptedStoredCredential(): void
    {
        $adapter = $this->adapter();
        $fixture = new WebAuthnFixtureFactory();
        $assertionOptions = $adapter->createAssertionOptions();
        $corrupted = new RegisteredCredential(
            credentialId: 'not valid base64url !!!',
            publicKey: $fixture->publicKey(),
            userHandle: $fixture->userHandle(),
            signCount: 0,
        );

        $this->expectException(InvalidWebAuthnAssertionException::class);

        $adapter->verifyAssertion(
            $assertionOptions,
            $fixture->assertionResponseJson($assertionOptions->challenge()),
            $corrupted,
        );
    }

    public function testConstructorRejectsAnUnsupportedUserVerificationRequirement(): void
    {
        $this->expectException(WebAuthnException::class);

        // 'discouraged' is deliberately not offered: the framework never weakens UV.
        new WebAuthnLibAdapter(
            WebAuthnFixtureFactory::RP_ID,
            'Waffle Test RP',
            [WebAuthnFixtureFactory::ORIGIN],
            'discouraged',
        );
    }

    public function testRequiredUserVerificationAdvertisesTheRequirementInTheOptions(): void
    {
        // The issued request options must carry userVerification:required so the
        // client ceremony actually performs UV and CheckUserVerification can enforce it.
        $options = $this->userVerifyingAdapter()->createAssertionOptions();

        self::assertStringContainsString('"userVerification":"required"', $options->toJson());
    }

    public function testRequiredUserVerificationAcceptsAnAssertionWithTheUvFlagSet(): void
    {
        $adapter = $this->userVerifyingAdapter();
        $fixture = new WebAuthnFixtureFactory();

        $registrationOptions = $adapter->createRegistrationOptions($this->user());
        $credential = $adapter->verifyRegistration(
            $registrationOptions,
            // Registration authenticator data sets UV (0x04) by default.
            $fixture->registrationResponseJson($registrationOptions->challenge()),
        );

        $assertionOptions = $adapter->createAssertionOptions([$credential]);
        $newSignCount = $adapter->verifyAssertion(
            $assertionOptions,
            $fixture->assertionResponseJson($assertionOptions->challenge(), 9, userVerified: true),
            $credential,
        );

        self::assertSame(9, $newSignCount);
    }

    public function testRequiredUserVerificationRejectsAnAssertionWithoutTheUvFlag(): void
    {
        $adapter = $this->userVerifyingAdapter();
        $fixture = new WebAuthnFixtureFactory();

        $registrationOptions = $adapter->createRegistrationOptions($this->user());
        $credential = $adapter->verifyRegistration(
            $registrationOptions,
            $fixture->registrationResponseJson($registrationOptions->challenge()),
        );

        $assertionOptions = $adapter->createAssertionOptions([$credential]);

        $this->expectException(InvalidWebAuthnAssertionException::class);

        // Same genuine signature & challenge, but the authenticator data clears the
        // UV flag — CheckUserVerification must reject because UV is 'required'.
        $adapter->verifyAssertion(
            $assertionOptions,
            $fixture->assertionResponseJson($assertionOptions->challenge(), 9, userVerified: false),
            $credential,
        );
    }

    public function testPreferredUserVerificationAcceptsAnAssertionWithoutTheUvFlag(): void
    {
        // Proves the default 'preferred' path does NOT enforce UV: the very same
        // UV-cleared assertion that 'required' rejects is accepted here.
        $adapter = $this->adapter();
        $fixture = new WebAuthnFixtureFactory();

        $registrationOptions = $adapter->createRegistrationOptions($this->user());
        $credential = $adapter->verifyRegistration(
            $registrationOptions,
            $fixture->registrationResponseJson($registrationOptions->challenge()),
        );

        $assertionOptions = $adapter->createAssertionOptions([$credential]);
        $newSignCount = $adapter->verifyAssertion(
            $assertionOptions,
            $fixture->assertionResponseJson($assertionOptions->challenge(), 9, userVerified: false),
            $credential,
        );

        self::assertSame(9, $newSignCount);
    }

    public function testRejectsAssertionWithACorruptedSignature(): void
    {
        // A genuine credential, genuine challenge & origin, but a bit-flipped
        // signature: CheckSignature must reject (not the challenge/origin checks).
        $adapter = $this->adapter();
        $fixture = new WebAuthnFixtureFactory();

        $registrationOptions = $adapter->createRegistrationOptions($this->user());
        $credential = $adapter->verifyRegistration(
            $registrationOptions,
            $fixture->registrationResponseJson($registrationOptions->challenge()),
        );

        $assertionOptions = $adapter->createAssertionOptions([$credential]);

        $this->expectException(InvalidWebAuthnAssertionException::class);

        $adapter->verifyAssertion(
            $assertionOptions,
            $fixture->assertionResponseJson($assertionOptions->challenge(), 9, corruptSignature: true),
            $credential,
        );
    }

    public function testRejectsAssertionWhoseUserHandleDoesNotMatchTheStoredCredential(): void
    {
        // Cross-user replay: a genuine, correctly-signed assertion from this
        // authenticator, but the wire userHandle belongs to a different user than
        // the stored credential's owner — the library's user-handle binding rejects it.
        $adapter = $this->adapter();
        $fixture = new WebAuthnFixtureFactory();

        $registrationOptions = $adapter->createRegistrationOptions($this->user());
        $credential = $adapter->verifyRegistration(
            $registrationOptions,
            $fixture->registrationResponseJson($registrationOptions->challenge()),
        );

        $assertionOptions = $adapter->createAssertionOptions([$credential]);

        $this->expectException(InvalidWebAuthnAssertionException::class);

        $adapter->verifyAssertion(
            $assertionOptions,
            $fixture->assertionResponseJson($assertionOptions->challenge(), 9, userHandle: 'a-different-users-handle'),
            $credential,
        );
    }
}
