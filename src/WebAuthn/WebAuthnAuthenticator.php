<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\WebAuthn;

use InvalidArgumentException;
use JsonException;
use Psr\Http\Message\ServerRequestInterface;
use Waffle\Commons\Auth\Identity\UserIdentity;
use Waffle\Commons\Auth\WebAuthn\Exception\InvalidWebAuthnAssertionException;
use Waffle\Commons\Contracts\Auth\AuthenticatorInterface;
use Waffle\Commons\Contracts\Auth\UserIdentityInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\CredentialRepositoryInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\WebAuthnVerifierInterface;

use function is_string;

/**
 * Inbound WebAuthn (passkey) scheme (AUTH-01) — mirrors {@see \Waffle\Commons\Auth\Authenticator\JwtAuthenticator}.
 *
 * `supports()` is a presence check only: does the request carry the
 * {@see self::CEREMONY_HEADER} that names a pending login ceremony? `authenticate()`
 * then replays the issued options from the injected
 * {@see WebAuthnChallengeStoreInterface}, looks up the asserted credential in the
 * app's {@see CredentialRepositoryInterface}, delegates the cryptographic check
 * to the {@see WebAuthnVerifierInterface}, advances the stored signature counter
 * (clone detection), and maps the result into a verified identity.
 *
 * Stateless (FrankenPHP rule): the challenge is never held in worker memory — the
 * store and the credential repository are injected and provided by the app.
 * Fail-closed: any missing piece or verification failure throws an
 * {@see \Waffle\Commons\Contracts\Auth\Exception\AuthenticationExceptionInterface}.
 */
final readonly class WebAuthnAuthenticator implements AuthenticatorInterface
{
    /** Header naming the pending login ceremony whose options were issued by the server. */
    public const string CEREMONY_HEADER = 'X-Wfl-Webauthn-Ceremony';

    public function __construct(
        private WebAuthnVerifierInterface $verifier,
        private WebAuthnChallengeStoreInterface $challenges,
        private CredentialRepositoryInterface $credentials,
    ) {}

    #[\Override]
    public function supports(ServerRequestInterface $request): bool
    {
        return $request->getHeaderLine(self::CEREMONY_HEADER) !== '';
    }

    #[\Override]
    public function authenticate(ServerRequestInterface $request): UserIdentityInterface
    {
        $ceremonyId = $request->getHeaderLine(self::CEREMONY_HEADER);
        if ($ceremonyId === '') {
            throw new InvalidWebAuthnAssertionException('Missing WebAuthn ceremony identifier.');
        }

        $options = $this->challenges->take($ceremonyId);
        if ($options === null) {
            throw new InvalidWebAuthnAssertionException('Unknown or expired WebAuthn login ceremony.');
        }

        $clientResponseJson = (string) $request->getBody();
        $credentialId = $this->credentialId($clientResponseJson);

        $credential = $this->credentials->findByCredentialId($credentialId);
        if ($credential === null) {
            throw new InvalidWebAuthnAssertionException('Unknown WebAuthn credential.');
        }

        $newSignCount = $this->verifier->verifyAssertion($options, $clientResponseJson, $credential);
        $this->credentials->updateSignCount($credentialId, $newSignCount);

        try {
            return new UserIdentity(subject: $credential->userHandle());
        } catch (InvalidArgumentException $e) {
            throw new InvalidWebAuthnAssertionException(
                'The verified WebAuthn credential has no usable user handle.',
                previous: $e,
            );
        }
    }

    /**
     * The (base64url) credential id the browser reported, used to locate the
     * stored passkey. The PSR-7 body is the scheme's untyped wire boundary, so
     * the `json_decode()` shape is narrowed by `is_string()` before use and a
     * malformed body fails closed.
     *
     * @throws InvalidWebAuthnAssertionException When the body is not a WebAuthn
     *         credential carrying a string `id`.
     */
    private function credentialId(string $clientResponseJson): string
    {
        try {
            $decoded = json_decode($clientResponseJson, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidWebAuthnAssertionException('The WebAuthn assertion body is not valid JSON.', previous: $e);
        }

        $id = is_array($decoded) ? $decoded['id'] ?? null : null;
        if (!is_string($id) || $id === '') {
            throw new InvalidWebAuthnAssertionException('The WebAuthn assertion body is missing a credential id.');
        }

        return $id;
    }
}
