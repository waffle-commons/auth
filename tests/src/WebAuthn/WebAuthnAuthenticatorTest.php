<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\WebAuthn;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Waffle\Commons\Auth\WebAuthn\Exception\InvalidWebAuthnAssertionException;
use Waffle\Commons\Auth\WebAuthn\WebAuthnAuthenticator;
use Waffle\Commons\Auth\WebAuthn\WebAuthnLibAdapter;
use Waffle\Commons\Auth\WebAuthn\WebAuthnUser;
use Waffle\Commons\Contracts\Auth\WebAuthn\AssertionOptionsInterface;
use WaffleTests\Commons\Auth\Helper\FakeServerRequest;
use WaffleTests\Commons\Auth\Helper\FakeStream;
use WaffleTests\Commons\Auth\WebAuthn\Helper\InMemoryChallengeStore;
use WaffleTests\Commons\Auth\WebAuthn\Helper\InMemoryCredentialRepository;
use WaffleTests\Commons\Auth\WebAuthn\Helper\StubCredential;
use WaffleTests\Commons\Auth\WebAuthn\Helper\StubVerifier;
use WaffleTests\Commons\Auth\WebAuthn\Helper\WebAuthnFixtureFactory;

#[CoversClass(WebAuthnAuthenticator::class)]
final class WebAuthnAuthenticatorTest extends TestCase
{
    private const string CEREMONY_ID = 'ceremony-1';

    private WebAuthnLibAdapter $adapter;

    private WebAuthnFixtureFactory $fixture;

    private InMemoryCredentialRepository $credentials;

    private InMemoryChallengeStore $challenges;

    protected function setUp(): void
    {
        $this->adapter = new WebAuthnLibAdapter(
            WebAuthnFixtureFactory::RP_ID,
            'Waffle Test RP',
            [WebAuthnFixtureFactory::ORIGIN],
        );
        $this->fixture = new WebAuthnFixtureFactory();
        $this->credentials = new InMemoryCredentialRepository();
        $this->challenges = new InMemoryChallengeStore();
    }

    private function authenticator(): WebAuthnAuthenticator
    {
        return new WebAuthnAuthenticator($this->adapter, $this->challenges, $this->credentials);
    }

    /** Enrol the fixture credential and stage a login ceremony, returning its options. */
    private function enrolAndStage(): AssertionOptionsInterface
    {
        $registrationOptions = $this->adapter->createRegistrationOptions(new WebAuthnUser(
            WebAuthnFixtureFactory::USER_HANDLE,
            'alice',
            'Alice',
        ));
        $credential = $this->adapter->verifyRegistration(
            $registrationOptions,
            $this->fixture->registrationResponseJson($registrationOptions->challenge()),
        );
        $this->credentials->save($credential);

        $options = $this->adapter->createAssertionOptions([$credential]);
        $this->challenges->put(self::CEREMONY_ID, $options);

        return $options;
    }

    private function request(string $body, string $ceremonyId = self::CEREMONY_ID): FakeServerRequest
    {
        $headers = $ceremonyId === '' ? [] : [WebAuthnAuthenticator::CEREMONY_HEADER => $ceremonyId];

        return new FakeServerRequest(headers: $headers)->withBody(new FakeStream($body));
    }

    public function testSupportsOnlyWhenTheCeremonyHeaderIsPresent(): void
    {
        $authenticator = $this->authenticator();

        self::assertTrue($authenticator->supports($this->request('', self::CEREMONY_ID)));
        self::assertFalse($authenticator->supports(new FakeServerRequest()));
    }

    public function testAuthenticatesAGenuineAssertionAndAdvancesTheSignCounter(): void
    {
        $options = $this->enrolAndStage();
        $request = $this->request($this->fixture->assertionResponseJson($options->challenge(), 12));

        $identity = $this->authenticator()->authenticate($request);

        self::assertSame($this->fixture->userHandle(), $identity->subject);
        self::assertSame(12, $this->credentials->signCountOf($this->fixture->credentialId()));
    }

    public function testRejectsAnUnknownCeremony(): void
    {
        $this->enrolAndStage();
        $request = $this->request('{"id":"x"}', 'never-issued');

        $this->expectException(InvalidWebAuthnAssertionException::class);

        $this->authenticator()->authenticate($request);
    }

    public function testRejectsAMalformedBody(): void
    {
        $this->enrolAndStage();
        $request = $this->request('{not-json');

        $this->expectException(InvalidWebAuthnAssertionException::class);

        $this->authenticator()->authenticate($request);
    }

    public function testRejectsABodyWithoutACredentialId(): void
    {
        $this->enrolAndStage();
        $request = $this->request('{"type":"public-key"}');

        $this->expectException(InvalidWebAuthnAssertionException::class);

        $this->authenticator()->authenticate($request);
    }

    public function testRejectsAnUnknownCredential(): void
    {
        $options = $this->enrolAndStage();
        $other = new WebAuthnFixtureFactory();
        $request = $this->request($other->assertionResponseJson($options->challenge()));

        $this->expectException(InvalidWebAuthnAssertionException::class);

        $this->authenticator()->authenticate($request);
    }

    public function testRejectsATamperedAssertion(): void
    {
        $this->enrolAndStage();
        // Stage a ceremony whose challenge does not match the signed response.
        $wrongOptions = $this->adapter->createAssertionOptions();
        $this->challenges->put('ceremony-2', $wrongOptions);
        $signedForAnotherChallenge = $this->fixture->assertionResponseJson(
            $this->adapter->createAssertionOptions()->challenge(),
        );
        $request = $this->request($signedForAnotherChallenge, 'ceremony-2');

        $this->expectException(InvalidWebAuthnAssertionException::class);

        $this->authenticator()->authenticate($request);
    }

    public function testRejectsACredentialWithAnEmptyUserHandle(): void
    {
        // A stored credential whose user handle is empty cannot become a verified
        // identity (UserIdentity requires a non-empty subject). The verifier is
        // stubbed to succeed so the authenticator's identity-construction guard is
        // exercised in isolation from the cryptographic core.
        $blankHandle = StubCredential::withUserHandle('');
        $this->credentials->save($blankHandle);
        $this->challenges->put(self::CEREMONY_ID, $this->adapter->createAssertionOptions());

        $authenticator = new WebAuthnAuthenticator(new StubVerifier(), $this->challenges, $this->credentials);
        $request = $this->request(sprintf('{"id":%s}', json_encode($blankHandle->credentialId())));

        $this->expectException(InvalidWebAuthnAssertionException::class);

        $authenticator->authenticate($request);
    }
}
