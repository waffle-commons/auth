<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Authenticator;

use Psr\Http\Message\ServerRequestInterface;
use Waffle\Commons\Auth\Identity\UserIdentity;
use Waffle\Commons\Contracts\Auth\Assertion\AssertionVerifierInterface;
use Waffle\Commons\Contracts\Auth\AuthenticatorInterface;
use Waffle\Commons\Contracts\Auth\Constant;
use Waffle\Commons\Contracts\Auth\UserIdentityInterface;

/**
 * Inbound Gateway Assertion scheme (RFC-021 §4.3): verifies the
 * `X-Wfl-Assert-User` header against the observed client IP and maps the
 * asserted claims into a verified identity. All cryptographic, temporal,
 * and IP-binding decisions belong to the {@see AssertionVerifierInterface}
 * — any violation throws an HTTP-403 exception (fail-closed).
 */
final readonly class AssertionAuthenticator implements AuthenticatorInterface
{
    public function __construct(
        private AssertionVerifierInterface $verifier,
    ) {}

    #[\Override]
    public function supports(ServerRequestInterface $request): bool
    {
        return $request->getHeaderLine(Constant::ASSERTION_HEADER) !== '';
    }

    #[\Override]
    public function authenticate(ServerRequestInterface $request): UserIdentityInterface
    {
        $assertion = $this->verifier->verify(
            headerValue: $request->getHeaderLine(Constant::ASSERTION_HEADER),
            expectedClientIp: self::remoteAddress($request),
        );

        return UserIdentity::fromAssertion($assertion);
    }

    /** The peer address as observed by this server (REMOTE_ADDR). */
    public static function remoteAddress(ServerRequestInterface $request): string
    {
        $remote = $request->getServerParams()['REMOTE_ADDR'] ?? '';

        return is_string($remote) ? $remote : '';
    }
}
