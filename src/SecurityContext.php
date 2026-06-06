<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth;

use Waffle\Commons\Contracts\Auth\SecurityContextInterface;
use Waffle\Commons\Contracts\Auth\UserIdentityInterface;

/**
 * Request-scoped holder of the authenticated identity (RFC-021 §4.1).
 *
 * This is the ONLY mutable service of the authentication component. It
 * implements `ResettableInterface` (via `SecurityContextInterface`) so the
 * container wipes it between FrankenPHP worker loops — `reset()` clears the
 * user state, roles, and client IP binding completely, preventing any
 * identity leak across consecutive requests (zero-leak mandate).
 */
final class SecurityContext implements SecurityContextInterface
{
    private ?UserIdentityInterface $identity = null;

    private ?string $clientIp = null;

    #[\Override]
    public function authenticate(UserIdentityInterface $identity, ?string $clientIp = null): void
    {
        // @igor-ignore: request-scoped identity holder BY DESIGN (RFC-021 §4.1); reset() wipes it between worker loops via ContainerInterface::reset().
        $this->identity = $identity;
        // @igor-ignore: request-scoped IP binding paired with the identity above; cleared by the same reset() path.
        $this->clientIp = $clientIp;
    }

    #[\Override]
    public function isAuthenticated(): bool
    {
        return $this->identity !== null;
    }

    #[\Override]
    public function getIdentity(): ?UserIdentityInterface
    {
        return $this->identity;
    }

    #[\Override]
    public function getClientIp(): ?string
    {
        return $this->clientIp;
    }

    #[\Override]
    public function reset(): void
    {
        $this->identity = null;
        $this->clientIp = null;
    }
}
