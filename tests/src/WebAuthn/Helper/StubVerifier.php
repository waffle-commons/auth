<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\WebAuthn\Helper;

use Waffle\Commons\Auth\WebAuthn\AssertionOptions;
use Waffle\Commons\Auth\WebAuthn\RegistrationOptions;
use Waffle\Commons\Contracts\Auth\WebAuthn\AssertionOptionsInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\RegisteredCredentialInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\RegistrationOptionsInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\WebAuthnUserInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\WebAuthnVerifierInterface;

/**
 * Verifier double that always succeeds, isolating the authenticator/ceremony
 * orchestration from the cryptographic core (covered against the real library by
 * {@see \WaffleTests\Commons\Auth\WebAuthn\WebAuthnLibAdapterTest}).
 */
final class StubVerifier implements WebAuthnVerifierInterface
{
    public function __construct(
        private readonly int $newSignCount = 1,
    ) {}

    #[\Override]
    public function createRegistrationOptions(
        WebAuthnUserInterface $user,
        array $existing = [],
    ): RegistrationOptionsInterface {
        return new RegistrationOptions('reg-challenge', '{"challenge":"reg-challenge"}');
    }

    #[\Override]
    public function verifyRegistration(
        RegistrationOptionsInterface $options,
        string $clientResponseJson,
    ): RegisteredCredentialInterface {
        return StubCredential::create();
    }

    #[\Override]
    public function createAssertionOptions(array $allowed = []): AssertionOptionsInterface
    {
        return new AssertionOptions('assert-challenge', '{"challenge":"assert-challenge"}');
    }

    #[\Override]
    public function verifyAssertion(
        AssertionOptionsInterface $options,
        string $clientResponseJson,
        RegisteredCredentialInterface $credential,
    ): int {
        return $this->newSignCount;
    }
}
