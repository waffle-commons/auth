<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\WebAuthn;

use InvalidArgumentException;
use Waffle\Commons\Contracts\Auth\WebAuthn\AssertionOptionsInterface;

/**
 * Server-issued options for a WebAuthn authentication (assertion) ceremony
 * (AUTH-01).
 *
 * Holds the (base64url) challenge bound to the pending login and the JSON the
 * library produced for `navigator.credentials.get()`. The same JSON is replayed
 * to {@see WebAuthnLibAdapter::verifyAssertion()} so assertion verification binds
 * to this challenge.
 *
 * PHP 8.5 property hooks validate the challenge at construction; asymmetric
 * `private(set)` visibility freezes the fields afterwards (hooked properties
 * cannot be `readonly`, so write-once `private(set)` provides immutability).
 */
final class AssertionOptions implements AssertionOptionsInterface
{
    /** The single-use, cryptographically-random challenge (base64url). Never empty. */
    public private(set) string $challenge {
        set(string $value) {
            if ($value === '') {
                throw new InvalidArgumentException('WebAuthn assertion challenge must not be empty.');
            }
            $this->challenge = $value;
        }
    }

    /** The library-serialized request options for the client `get()` call. Never empty. */
    public private(set) string $json {
        set(string $value) {
            if ($value === '') {
                throw new InvalidArgumentException('WebAuthn assertion options JSON must not be empty.');
            }
            $this->json = $value;
        }
    }

    public function __construct(string $challenge, string $json)
    {
        $this->challenge = $challenge;
        $this->json = $json;
    }

    #[\Override]
    public function challenge(): string
    {
        return $this->challenge;
    }

    /**
     * @return array<string, mixed>
     *
     * @throws \Waffle\Commons\Auth\WebAuthn\Exception\WebAuthnException When the
     *         stored options JSON is corrupted (not a decodable object).
     */
    #[\Override]
    public function toArray(): array
    {
        return OptionsCodec::decode($this->json);
    }

    #[\Override]
    public function toJson(): string
    {
        return $this->json;
    }
}
