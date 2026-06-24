<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\WebAuthn\Helper;

use Waffle\Commons\Contracts\Auth\WebAuthn\RegisteredCredentialInterface;

/** Configurable credential double for ceremony/authenticator orchestration tests. */
final class StubCredential implements RegisteredCredentialInterface
{
    /**
     * @param list<string> $transports
     */
    public function __construct(
        private readonly string $credentialId = 'stub-credential-id',
        private readonly string $publicKey = 'stub-public-key',
        private readonly string $userHandle = 'stub-user-handle',
        private readonly int $signCount = 0,
        private readonly array $transports = ['internal'],
    ) {}

    public static function create(): self
    {
        return new self();
    }

    public static function withUserHandle(string $userHandle): self
    {
        return new self(userHandle: $userHandle);
    }

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
