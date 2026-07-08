<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\WebAuthn;

use Waffle\Commons\Contracts\Auth\WebAuthn\RegisteredCredentialInterface;

/**
 * A passkey enrolled for a user (AUTH-01) — the persistent product of a
 * successful registration ceremony.
 *
 * Maps to the library's `CredentialRecord`. Every binary field is carried as a
 * base64url string so the value object is JSON/storage friendly and the
 * stateful {@see \Waffle\Commons\Contracts\Auth\WebAuthn\CredentialRepositoryInterface}
 * persists exactly what it receives.
 */
final readonly class RegisteredCredential implements RegisteredCredentialInterface
{
    /**
     * @param list<string> $transports
     */
    public function __construct(
        private string $credentialId,
        private string $publicKey,
        private string $userHandle,
        private int $signCount,
        private array $transports = [],
    ) {}

    #[\Override]
    public function credentialId(): string
    {
        return $this->credentialId;
    }

    #[\Override]
    public function publicKey(): string
    {
        return $this->publicKey;
    }

    #[\Override]
    public function userHandle(): string
    {
        return $this->userHandle;
    }

    #[\Override]
    public function signCount(): int
    {
        return $this->signCount;
    }

    /**
     * @return list<string>
     */
    #[\Override]
    public function transports(): array
    {
        return $this->transports;
    }
}
