<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Authenticator;

use Psr\Http\Message\ServerRequestInterface;
use Waffle\Commons\Auth\Exception\AuthenticationException;
use Waffle\Commons\Auth\Identity\UserIdentity;
use Waffle\Commons\Contracts\Auth\AuthenticatorInterface;
use Waffle\Commons\Contracts\Auth\Constant;
use Waffle\Commons\Contracts\Auth\UserIdentityInterface;

/**
 * Inbound HTTP Basic scheme (RFC 7617, RFC-021 §4.6).
 *
 * Credentials are validated in constant time: `password_verify()` when the
 * configured secret is a password hash (`password_hash()` output), or
 * `hash_equals()` for opaque shared tokens. Plain-text password storage is
 * the caller's responsibility to avoid — hashes are strongly recommended.
 */
final readonly class BasicAuthenticator implements AuthenticatorInterface
{
    /**
     * @param array<string, string> $users     Map of username → password hash
     *                                         (preferred) or opaque token.
     * @param list<string>          $roles     Roles granted to every Basic
     *                                         identity (scheme-level grant).
     */
    public function __construct(
        #[\SensitiveParameter]
        private array $users,
        private array $roles = [],
    ) {}

    #[\Override]
    public function supports(ServerRequestInterface $request): bool
    {
        return str_starts_with($request->getHeaderLine(Constant::AUTHORIZATION_HEADER), Constant::BASIC_PREFIX);
    }

    #[\Override]
    public function authenticate(ServerRequestInterface $request): UserIdentityInterface
    {
        $encoded = substr($request->getHeaderLine(Constant::AUTHORIZATION_HEADER), strlen(Constant::BASIC_PREFIX));

        $decoded = base64_decode($encoded, strict: true);
        if ($decoded === false) {
            throw new AuthenticationException('Malformed Basic credentials.');
        }

        $separator = strpos($decoded, ':');
        if ($separator === false) {
            throw new AuthenticationException('Malformed Basic credentials.');
        }

        $username = substr($decoded, 0, $separator);
        $password = substr($decoded, $separator + 1);

        $known = $this->users[$username] ?? null;
        if ($known === null || !$this->matches($known, $password)) {
            throw new AuthenticationException('Invalid Basic credentials.');
        }

        try {
            return new UserIdentity(subject: $username, roles: $this->roles);
        } catch (\InvalidArgumentException $e) {
            // Empty username — schema violation surfaces as a 401, never a 500.
            throw new AuthenticationException('Invalid Basic credentials.', previous: $e);
        }
    }

    /** Constant-time credential comparison (hash-aware). */
    private function matches(#[\SensitiveParameter] string $known, #[\SensitiveParameter] string $candidate): bool
    {
        // `password_hash()` outputs always carry a crypt-style `$<id>$` prefix.
        if (str_starts_with($known, '$2y$') || str_starts_with($known, '$2a$') || str_starts_with($known, '$argon2')) {
            return password_verify($candidate, $known);
        }

        return hash_equals($known, $candidate);
    }
}
