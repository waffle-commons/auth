<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Helper;

use Waffle\Commons\Contracts\Auth\Assertion\UserAssertionInterface;

/**
 * Interface-level fixture carrying claims a verifier would never produce —
 * exercises the defensive identity-schema conversion in
 * `UserIdentity::fromAssertion()`.
 */
final class SchemaViolatingAssertion implements UserAssertionInterface
{
    public string $subject {
        get => '';
    }

    public ?string $email {
        get => null;
    }

    /** @var list<string> */
    public array $roles {
        get => [];
    }

    public ?string $tenant {
        get => null;
    }

    public int $issuedAt {
        get => 1_000;
    }

    public int $expiresAt {
        get => 1_005;
    }

    public string $ipHash {
        get => str_repeat('ab', 32);
    }

    public string $payload {
        get => '{}';
    }
}
