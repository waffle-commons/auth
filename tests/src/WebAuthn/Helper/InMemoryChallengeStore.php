<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\WebAuthn\Helper;

use Waffle\Commons\Auth\WebAuthn\WebAuthnChallengeStoreInterface;
use Waffle\Commons\Contracts\Auth\WebAuthn\AssertionOptionsInterface;

/** Hermetic single-use challenge store standing in for the app's session/cache. */
final class InMemoryChallengeStore implements WebAuthnChallengeStoreInterface
{
    /** @var array<string, AssertionOptionsInterface> */
    private array $options = [];

    public function put(string $ceremonyId, AssertionOptionsInterface $options): void
    {
        $this->options[$ceremonyId] = $options;
    }

    #[\Override]
    public function take(string $ceremonyId): ?AssertionOptionsInterface
    {
        $options = $this->options[$ceremonyId] ?? null;
        unset($this->options[$ceremonyId]);

        return $options;
    }
}
