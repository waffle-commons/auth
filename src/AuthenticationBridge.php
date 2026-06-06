<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth;

use Psr\Http\Message\ServerRequestInterface;
use Waffle\Commons\Auth\Authenticator\AssertionAuthenticator;
use Waffle\Commons\Contracts\Auth\AuthenticationBridgeInterface;
use Waffle\Commons\Contracts\Auth\AuthenticatorInterface;
use Waffle\Commons\Contracts\Auth\SecurityContextInterface;
use Waffle\Commons\Contracts\Auth\UserIdentityInterface;

/**
 * The Universal Authentication Bridge orchestrator (RFC-021 §3.2).
 *
 * Strict rules:
 *  1. first scheme whose `supports()` matches wins — later schemes are
 *     never consulted;
 *  2. a supporting scheme that rejects credentials throws and the exception
 *     propagates (fail-closed, no fallback, no anonymous downgrade);
 *  3. when no scheme supports the request the bridge returns null —
 *     anonymous is explicit and authorization (RFC-002) decides access.
 *
 * On success the verified identity and the observed client IP are stored
 * in the request-scoped {@see SecurityContextInterface}.
 */
final readonly class AuthenticationBridge implements AuthenticationBridgeInterface
{
    /**
     * @param SecurityContextInterface     $context        Request-scoped identity holder.
     * @param list<AuthenticatorInterface> $authenticators Schemes, in priority order.
     */
    public function __construct(
        private SecurityContextInterface $context,
        private array $authenticators,
    ) {}

    #[\Override]
    public function authenticate(ServerRequestInterface $request): ?UserIdentityInterface
    {
        foreach ($this->authenticators as $authenticator) {
            if (!$authenticator->supports($request)) {
                continue;
            }

            $identity = $authenticator->authenticate($request);
            $this->context->authenticate($identity, AssertionAuthenticator::remoteAddress($request));

            return $identity;
        }

        return null;
    }
}
