<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\WebAuthn;

use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Uid\NilUuid;
use Throwable;
use Waffle\Commons\Auth\Codec\Base64Url;
use Waffle\Commons\Auth\WebAuthn\Exception\InvalidWebAuthnAssertionException;
use Waffle\Commons\Auth\WebAuthn\Exception\InvalidWebAuthnRegistrationException;
use Waffle\Commons\Auth\WebAuthn\Exception\WebAuthnException;
use Waffle\Commons\Contracts\Auth\WebAuthn\AssertionOptionsInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\RegisteredCredentialInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\RegistrationOptionsInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\WebAuthnUserInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\WebAuthnVerifierInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * The cryptographic core of WebAuthn (AUTH-01) — the ONLY class that imports the
 * audited `web-auth/webauthn-lib` (`Webauthn\**`), so the framework never
 * hand-rolls CBOR/COSE/attestation parsing.
 *
 * The adapter is stateless: the serializer and both ceremony validators are
 * built once at construction from the relying-party configuration and reused
 * read-only across requests (FrankenPHP worker rule). Challenge persistence and
 * credential storage live OUTSIDE this class (the app's challenge store and
 * {@see \Waffle\Commons\Contracts\Auth\WebAuthn\CredentialRepositoryInterface}).
 *
 * The library exposes its option/response objects through typed serializers, so
 * the only `string`→object boundary is the client-supplied JSON, which is fed
 * straight to the serializer and never read as raw `mixed`.
 */
final class WebAuthnLibAdapter implements WebAuthnVerifierInterface
{
    /**
     * COSE algorithm identifier for ECDSA over P-256 with SHA-256 (ES256),
     * the mandatory-to-implement passkey algorithm (IANA COSE registry, RFC 9053).
     */
    private const int COSE_ALGORITHM_ES256 = -7;

    /** COSE algorithm identifier for RSASSA-PKCS1-v1_5 with SHA-256 (RS256). */
    private const int COSE_ALGORITHM_RS256 = -257;

    /**
     * Accepted user-verification (UV) requirements (WebAuthn §5.4.3). `'preferred'`
     * lets the authenticator decide; `'required'` makes the library's
     * {@see \Webauthn\CeremonyStep\CheckUserVerification} reject any response whose
     * authenticator data lacks the UV flag. `'discouraged'` is intentionally NOT
     * offered: the framework never weakens UV below the protocol default.
     */
    private const array USER_VERIFICATION_REQUIREMENTS = [
        AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
        AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
    ];

    private SerializerInterface $serializer;

    private AuthenticatorAttestationResponseValidator $attestationValidator;

    private AuthenticatorAssertionResponseValidator $assertionValidator;

    private PublicKeyCredentialRpEntity $relyingParty;

    /**
     * @param string       $relyingPartyId   The relying-party id (an effective domain, e.g. `example.com`).
     * @param string       $relyingPartyName Human-facing relying-party name shown by the authenticator UI.
     * @param list<string> $allowedOrigins   Acceptable client origins (e.g. `https://example.com`).
     * @param string       $userVerification User-verification (UV) requirement applied to BOTH ceremonies;
     *        accepts `'preferred'` (default) or `'required'`. Set `'required'` for passwordless logins so
     *        the library's `CheckUserVerification` step rejects any response missing the UV flag. The
     *        value is validated at construction (untyped config may reach it), so a bad value is rejected
     *        fail-closed rather than silently widening UV.
     *
     * @throws WebAuthnException When an unsupported user-verification requirement is given (fail-closed).
     */
    public function __construct(
        private string $relyingPartyId,
        string $relyingPartyName,
        array $allowedOrigins,
        private string $userVerification = AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
    ) {
        if (!in_array($this->userVerification, self::USER_VERIFICATION_REQUIREMENTS, true)) {
            throw new WebAuthnException(sprintf(
                'Unsupported WebAuthn user-verification requirement "%s"; expected "preferred" or "required".',
                $this->userVerification,
            ));
        }

        $this->relyingParty = PublicKeyCredentialRpEntity::create($relyingPartyName, $relyingPartyId);

        $attestationSupportManager = AttestationStatementSupportManager::create();
        $attestationSupportManager->add(NoneAttestationStatementSupport::create());
        $this->serializer = new WebauthnSerializerFactory($attestationSupportManager)->create();

        $ceremonyFactory = new CeremonyStepManagerFactory();
        $ceremonyFactory->setAllowedOrigins($allowedOrigins);
        $this->attestationValidator = AuthenticatorAttestationResponseValidator::create(
            $ceremonyFactory->creationCeremony(),
        );
        $this->assertionValidator = AuthenticatorAssertionResponseValidator::create(
            $ceremonyFactory->requestCeremony(),
        );
    }

    /**
     * @param list<RegisteredCredentialInterface> $existing
     *
     * @throws WebAuthnException When the options cannot be built or serialized
     *         (a server-side failure; fail-closed).
     */
    #[\Override]
    public function createRegistrationOptions(
        WebAuthnUserInterface $user,
        array $existing = [],
    ): RegistrationOptionsInterface {
        try {
            $excludeCredentials = [];
            foreach ($existing as $credential) {
                $excludeCredentials[] = PublicKeyCredentialDescriptor::create(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    $this->decode($credential->credentialId()),
                    $credential->transports(),
                );
            }

            $options = PublicKeyCredentialCreationOptions::create(
                $this->relyingParty,
                PublicKeyCredentialUserEntity::create($user->name(), $user->id(), $user->displayName()),
                random_bytes(32),
                [
                    PublicKeyCredentialParameters::createPk(self::COSE_ALGORITHM_ES256),
                    PublicKeyCredentialParameters::createPk(self::COSE_ALGORITHM_RS256),
                ],
                // Carry the configured UV requirement on the registration ceremony too:
                // when `'required'`, `CheckUserVerification` reads it from authenticatorSelection
                // and rejects an attestation whose authenticator data lacks the UV flag.
                authenticatorSelection: AuthenticatorSelectionCriteria::create(userVerification: $this->userVerification),
                attestation: PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
                excludeCredentials: $excludeCredentials,
            );

            return new RegistrationOptions(Base64Url::encode($options->challenge), $this->serialize($options));
        } catch (WebAuthnException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new WebAuthnException('Failed to build the WebAuthn registration options.', previous: $e);
        }
    }

    /**
     * @throws InvalidWebAuthnRegistrationException When attestation verification
     *         fails (the credential is never enrolled).
     */
    #[\Override]
    public function verifyRegistration(
        RegistrationOptionsInterface $options,
        string $clientResponseJson,
    ): RegisteredCredentialInterface {
        try {
            $creationOptions = $this->serializer->deserialize(
                $options->toJson(),
                PublicKeyCredentialCreationOptions::class,
                'json',
            );
            $response = $this->deserializeResponse($clientResponseJson);
            if (!$response instanceof AuthenticatorAttestationResponse) {
                throw new InvalidWebAuthnRegistrationException(
                    'The client response is not a WebAuthn attestation (registration) response.',
                );
            }

            $record = $this->attestationValidator->check($response, $creationOptions, $this->relyingPartyId);
        } catch (InvalidWebAuthnRegistrationException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new InvalidWebAuthnRegistrationException('WebAuthn attestation verification failed.', previous: $e);
        }

        return $this->toRegisteredCredential($record);
    }

    /**
     * @param list<RegisteredCredentialInterface> $allowed
     *
     * @throws WebAuthnException When the options cannot be built or serialized
     *         (a server-side failure; fail-closed).
     */
    #[\Override]
    public function createAssertionOptions(array $allowed = []): AssertionOptionsInterface
    {
        try {
            $allowCredentials = [];
            foreach ($allowed as $credential) {
                $allowCredentials[] = PublicKeyCredentialDescriptor::create(
                    PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                    $this->decode($credential->credentialId()),
                    $credential->transports(),
                );
            }

            $options = PublicKeyCredentialRequestOptions::create(
                random_bytes(32),
                $this->relyingPartyId,
                $allowCredentials,
                // The UV requirement the client `get()` ceremony advertises and the server
                // enforces: when `'required'`, `CheckUserVerification` rejects an assertion
                // whose authenticator data lacks the UV flag (passwordless-login hardening).
                userVerification: $this->userVerification,
            );

            return new AssertionOptions(Base64Url::encode($options->challenge), $this->serialize($options));
        } catch (WebAuthnException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new WebAuthnException('Failed to build the WebAuthn assertion options.', previous: $e);
        }
    }

    /**
     * @throws InvalidWebAuthnAssertionException When assertion verification fails.
     */
    #[\Override]
    public function verifyAssertion(
        AssertionOptionsInterface $options,
        string $clientResponseJson,
        RegisteredCredentialInterface $credential,
    ): int {
        try {
            $requestOptions = $this->serializer->deserialize(
                $options->toJson(),
                PublicKeyCredentialRequestOptions::class,
                'json',
            );
            $response = $this->deserializeResponse($clientResponseJson);
            if (!$response instanceof AuthenticatorAssertionResponse) {
                throw new InvalidWebAuthnAssertionException(
                    'The client response is not a WebAuthn assertion (login) response.',
                );
            }

            $verified = $this->assertionValidator->check(
                $this->toCredentialRecord($credential),
                $response,
                $requestOptions,
                $this->relyingPartyId,
                $credential->userHandle(),
            );
        } catch (InvalidWebAuthnAssertionException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new InvalidWebAuthnAssertionException('WebAuthn assertion verification failed.', previous: $e);
        }

        return $verified->counter;
    }

    /**
     * Deserialize the client ceremony response into the library credential's
     * inner authenticator response.
     *
     * @throws WebAuthnException When the response does not decode to a known
     *         authenticator response.
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface When the
     *         library's serializer rejects the JSON shape.
     */
    private function deserializeResponse(string $clientResponseJson): AuthenticatorAttestationResponse|AuthenticatorAssertionResponse
    {
        $credential = $this->serializer->deserialize($clientResponseJson, PublicKeyCredential::class, 'json');

        $response = $credential->response;
        if (
            !$response instanceof AuthenticatorAttestationResponse
            && !$response instanceof AuthenticatorAssertionResponse
        ) {
            throw new WebAuthnException('The WebAuthn client response carries an unknown authenticator response.');
        }

        return $response;
    }

    /**
     * @throws \Symfony\Component\Serializer\Exception\ExceptionInterface When the
     *         library's serializer cannot encode the options.
     */
    private function serialize(PublicKeyCredentialCreationOptions|PublicKeyCredentialRequestOptions $options): string
    {
        return $this->serializer->serialize($options, 'json');
    }

    private function toRegisteredCredential(CredentialRecord $record): RegisteredCredential
    {
        $transports = [];
        foreach ($record->transports as $transport) {
            $transports[] = $transport;
        }

        return new RegisteredCredential(
            credentialId: Base64Url::encode($record->publicKeyCredentialId),
            publicKey: Base64Url::encode($record->credentialPublicKey),
            // The user handle is the app's opaque, stable identifier (matching
            // WebAuthnUserInterface::id()), not raw authenticator bytes, so it is
            // carried verbatim — keeping it equal to the value a repository keys on.
            userHandle: $record->userHandle,
            signCount: $record->counter,
            transports: $transports,
        );
    }

    /**
     * @throws WebAuthnException When a stored credential field is not base64url.
     */
    private function toCredentialRecord(RegisteredCredentialInterface $credential): CredentialRecord
    {
        return CredentialRecord::create(
            publicKeyCredentialId: $this->decode($credential->credentialId()),
            type: PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            transports: $credential->transports(),
            attestationType: 'none',
            trustPath: EmptyTrustPath::create(),
            aaguid: new NilUuid(),
            credentialPublicKey: $this->decode($credential->publicKey()),
            userHandle: $credential->userHandle(),
            counter: $credential->signCount(),
        );
    }

    /**
     * Strict base64url decode of a stored credential field.
     *
     * @throws WebAuthnException When the stored value is not valid base64url
     *         (a corrupted credential store; fail-closed).
     */
    private function decode(string $value): string
    {
        $decoded = Base64Url::decode($value);
        if ($decoded === null) {
            throw new WebAuthnException('A stored WebAuthn credential field is not valid base64url.');
        }

        return $decoded;
    }
}
