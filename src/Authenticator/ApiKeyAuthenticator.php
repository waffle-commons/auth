<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Authenticator;

use Psr\Http\Message\ServerRequestInterface;
use Waffle\Commons\Auth\Exception\AuthenticationException;
use Waffle\Commons\Contracts\Auth\AuthenticatorInterface;
use Waffle\Commons\Contracts\Auth\Constant;
use Waffle\Commons\Contracts\Auth\UserIdentityInterface;

/**
 * Inbound API-key scheme (RFC-021 §4.6).
 *
 * Matches the configured header (default `X-Api-Key`) against the key →
 * identity map using `hash_equals()` — constant time per candidate, no
 * dictionary lookup on the secret value.
 */
final readonly class ApiKeyAuthenticator implements AuthenticatorInterface
{
    /**
     * @param array<string, UserIdentityInterface> $identitiesByKey Map of
     *        opaque API key → the identity it authenticates.
     * @param string $headerName Header carrying the key.
     */
    public function __construct(
        #[\SensitiveParameter]
        private array $identitiesByKey,
        private string $headerName = Constant::API_KEY_HEADER,
    ) {}

    #[\Override]
    public function supports(ServerRequestInterface $request): bool
    {
        return $request->getHeaderLine($this->headerName) !== '';
    }

    #[\Override]
    public function authenticate(ServerRequestInterface $request): UserIdentityInterface
    {
        $candidate = $request->getHeaderLine($this->headerName);

        foreach ($this->identitiesByKey as $knownKey => $identity) {
            if (hash_equals($knownKey, $candidate)) {
                return $identity;
            }
        }

        throw new AuthenticationException('Invalid API key.');
    }
}
