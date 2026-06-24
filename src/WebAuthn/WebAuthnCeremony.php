<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\WebAuthn;

use Waffle\Commons\Contracts\Auth\WebAuthn\AssertionOptionsInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\CredentialRepositoryInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\Exception\InvalidWebAuthnRegistrationExceptionInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\RegisteredCredentialInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\RegistrationOptionsInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\WebAuthnUserInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\WebAuthnVerifierInterface;

/**
 * Registration (enrolment) ceremony service for WebAuthn passkeys (AUTH-01).
 *
 * Bookends the attestation ceremony, separate from the inbound
 * {@see WebAuthnAuthenticator}: it issues the creation options to send the
 * browser and, on a verified attestation response, persists the new credential
 * through the app's {@see CredentialRepositoryInterface}. It also issues login
 * options scoped to a user's enrolled passkeys.
 *
 * Stateless: the challenge that {@see self::startRegistration()} mints travels in
 * the returned options for the app to persist against the pending ceremony — it
 * is never held in worker memory — and is replayed to
 * {@see self::finishRegistration()}. Credential storage is the injected
 * repository, never this service.
 */
final readonly class WebAuthnCeremony
{
    public function __construct(
        private WebAuthnVerifierInterface $verifier,
        private CredentialRepositoryInterface $credentials,
    ) {}

    /**
     * Build registration options for enrolling a new passkey, excluding the
     * user's already-enrolled credentials to prevent double-registration.
     */
    public function startRegistration(WebAuthnUserInterface $user): RegistrationOptionsInterface
    {
        return $this->verifier->createRegistrationOptions($user, $this->credentials->findByUserHandle($user->id()));
    }

    /**
     * Verify an attestation response against the issued options and persist the
     * resulting credential, returning what was stored.
     *
     * @throws InvalidWebAuthnRegistrationExceptionInterface When attestation
     *         verification fails (the credential is never persisted).
     */
    public function finishRegistration(
        RegistrationOptionsInterface $options,
        string $clientResponseJson,
    ): RegisteredCredentialInterface {
        $credential = $this->verifier->verifyRegistration($options, $clientResponseJson);
        $this->credentials->save($credential);

        return $credential;
    }

    /**
     * Build login options scoped to the passkeys enrolled for the given user
     * handle; an unknown handle yields a usernameless/discoverable login.
     */
    public function startAuthentication(string $userHandle): AssertionOptionsInterface
    {
        return $this->verifier->createAssertionOptions($this->credentials->findByUserHandle($userHandle));
    }
}
