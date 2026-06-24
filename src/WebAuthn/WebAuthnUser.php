<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\WebAuthn;

use Waffle\Commons\Contracts\Auth\WebAuthn\WebAuthnUserInterface;

/**
 * The user a registration ceremony enrols a passkey for (AUTH-01).
 *
 * Maps to a WebAuthn `PublicKeyCredentialUserEntity`. The {@see self::id()}
 * handle MUST be a stable, opaque, non-PII surrogate (WebAuthn §4) — never an
 * email. The library caps the handle at 64 bytes, so values longer than that
 * are rejected by the verifier when the options are built.
 */
final readonly class WebAuthnUser implements WebAuthnUserInterface
{
    public function __construct(
        private string $id,
        private string $name,
        private string $displayName,
    ) {}

    #[\Override]
    public function id(): string
    {
        return $this->id;
    }

    #[\Override]
    public function name(): string
    {
        return $this->name;
    }

    #[\Override]
    public function displayName(): string
    {
        return $this->displayName;
    }
}
