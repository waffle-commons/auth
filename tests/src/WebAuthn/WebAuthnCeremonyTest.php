<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\WebAuthn;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Waffle\Commons\Auth\WebAuthn\Exception\InvalidWebAuthnRegistrationException;
use Waffle\Commons\Auth\WebAuthn\WebAuthnCeremony;
use Waffle\Commons\Auth\WebAuthn\WebAuthnLibAdapter;
use Waffle\Commons\Auth\WebAuthn\WebAuthnUser;
use WaffleTests\Commons\Auth\WebAuthn\Helper\InMemoryCredentialRepository;
use WaffleTests\Commons\Auth\WebAuthn\Helper\StubVerifier;
use WaffleTests\Commons\Auth\WebAuthn\Helper\WebAuthnFixtureFactory;

#[CoversClass(WebAuthnCeremony::class)]
final class WebAuthnCeremonyTest extends TestCase
{
    private WebAuthnLibAdapter $adapter;

    private WebAuthnFixtureFactory $fixture;

    private InMemoryCredentialRepository $credentials;

    protected function setUp(): void
    {
        $this->adapter = new WebAuthnLibAdapter(
            WebAuthnFixtureFactory::RP_ID,
            'Waffle Test RP',
            [WebAuthnFixtureFactory::ORIGIN],
        );
        $this->fixture = new WebAuthnFixtureFactory();
        $this->credentials = new InMemoryCredentialRepository();
    }

    private function ceremony(): WebAuthnCeremony
    {
        return new WebAuthnCeremony($this->adapter, $this->credentials);
    }

    private function user(): WebAuthnUser
    {
        return new WebAuthnUser(WebAuthnFixtureFactory::USER_HANDLE, 'alice', 'Alice');
    }

    public function testStartRegistrationIssuesOptions(): void
    {
        $options = $this->ceremony()->startRegistration($this->user());

        self::assertNotSame('', $options->challenge());
    }

    public function testFinishRegistrationVerifiesAndPersistsTheCredential(): void
    {
        $ceremony = $this->ceremony();
        $options = $ceremony->startRegistration($this->user());

        $credential = $ceremony->finishRegistration(
            $options,
            $this->fixture->registrationResponseJson($options->challenge()),
        );

        self::assertSame($this->fixture->credentialId(), $credential->credentialId());
        self::assertNotNull($this->credentials->findByCredentialId($this->fixture->credentialId()));
    }

    public function testFinishRegistrationDoesNotPersistOnFailure(): void
    {
        $ceremony = $this->ceremony();
        $options = $ceremony->startRegistration($this->user());

        try {
            $ceremony->finishRegistration($options, $this->fixture->registrationResponseJson(
                $options->challenge(),
                'https://evil.example.com',
            ));
            self::fail('Expected a registration failure.');
        } catch (InvalidWebAuthnRegistrationException $e) {
            self::assertSame(400, $e->getCode());
        }

        self::assertNull($this->credentials->findByCredentialId($this->fixture->credentialId()));
    }

    public function testStartRegistrationExcludesAlreadyEnrolledCredentials(): void
    {
        $ceremony = $this->ceremony();
        $first = $ceremony->startRegistration($this->user());
        $credential = $ceremony->finishRegistration(
            $first,
            $this->fixture->registrationResponseJson($first->challenge()),
        );

        $second = $ceremony->startRegistration($this->user());

        self::assertStringContainsString($credential->credentialId(), $second->toJson());
    }

    public function testStartAuthenticationScopesOptionsToEnrolledPasskeys(): void
    {
        $ceremony = $this->ceremony();
        $registration = $ceremony->startRegistration($this->user());
        $credential = $ceremony->finishRegistration(
            $registration,
            $this->fixture->registrationResponseJson($registration->challenge()),
        );

        $options = $ceremony->startAuthentication(WebAuthnFixtureFactory::USER_HANDLE);

        self::assertStringContainsString($credential->credentialId(), $options->toJson());
    }

    public function testStartAuthenticationForAnUnknownUserYieldsDiscoverableLogin(): void
    {
        $options = new WebAuthnCeremony(new StubVerifier(), $this->credentials)->startAuthentication('nobody');

        self::assertSame('assert-challenge', $options->challenge());
    }
}
