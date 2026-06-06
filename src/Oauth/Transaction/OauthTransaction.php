<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Oauth\Transaction;

use InvalidArgumentException;
use Waffle\Commons\Auth\Oauth\Pkce;

/**
 * One in-flight OAuth login transaction (RFC-021 §4.5): the `state`,
 * `nonce`, and PKCE verifier minted at redirect time, carried statelessly
 * in a signed cookie until the provider calls back.
 */
final readonly class OauthTransaction
{
    /**
     * @throws InvalidArgumentException Empty state, nonce, or verifier.
     */
    public function __construct(
        public string $state,
        public string $nonce,
        #[\SensitiveParameter]
        public string $codeVerifier,
        public string $returnTo = '/',
    ) {
        if ($this->state === '' || $this->nonce === '' || $this->codeVerifier === '') {
            throw new InvalidArgumentException('OAuth transaction requires non-empty state, nonce, and verifier.');
        }
    }

    /**
     * Mints a fresh transaction with high-entropy values.
     *
     * @throws \Random\RandomException   The platform CSPRNG is unavailable.
     * @throws InvalidArgumentException  Unreachable in practice: the minted
     *         values are always non-empty (declared for `check-throws`).
     */
    public static function start(string $returnTo = '/'): self
    {
        return new self(
            state: bin2hex(random_bytes(16)),
            nonce: bin2hex(random_bytes(16)),
            codeVerifier: Pkce::generateVerifier(),
            returnTo: $returnTo,
        );
    }
}
