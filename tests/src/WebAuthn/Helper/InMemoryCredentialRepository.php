<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\WebAuthn\Helper;

use Waffle\Commons\Auth\WebAuthn\RegisteredCredential;
use Waffle\Commons\Contracts\Auth\WebAuthn\CredentialRepositoryInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\RegisteredCredentialInterface;

/** Hermetic in-memory credential store standing in for the app's persistence. */
final class InMemoryCredentialRepository implements CredentialRepositoryInterface
{
    /** @var array<string, RegisteredCredentialInterface> Keyed by credential id. */
    private array $byCredentialId = [];

    #[\Override]
    public function findByCredentialId(string $credentialId): ?RegisteredCredentialInterface
    {
        return $this->byCredentialId[$credentialId] ?? null;
    }

    /**
     * @return list<RegisteredCredentialInterface>
     */
    #[\Override]
    public function findByUserHandle(string $userHandle): array
    {
        $found = [];
        foreach ($this->byCredentialId as $credential) {
            if ($credential->userHandle() !== $userHandle) {
                continue;
            }

            $found[] = $credential;
        }

        return $found;
    }

    #[\Override]
    public function save(RegisteredCredentialInterface $credential): void
    {
        $this->byCredentialId[$credential->credentialId()] = $credential;
    }

    #[\Override]
    public function updateSignCount(string $credentialId, int $signCount): void
    {
        $existing = $this->byCredentialId[$credentialId] ?? null;
        if ($existing === null) {
            return;
        }

        $this->byCredentialId[$credentialId] = new RegisteredCredential(
            credentialId: $existing->credentialId(),
            publicKey: $existing->publicKey(),
            userHandle: $existing->userHandle(),
            signCount: $signCount,
            transports: $existing->transports(),
        );
    }

    /** The signature counter currently stored for a credential, for assertions. */
    public function signCountOf(string $credentialId): ?int
    {
        return ($this->byCredentialId[$credentialId] ?? null)?->signCount();
    }
}
