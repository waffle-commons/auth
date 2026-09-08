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
    /** Timing-safe-comparison filler for a $known that isn't a real opaque token. */
    private const string COMPARISON_FILLER = 'waffle-never-a-real-configured-value';

    /**
     * Valid-shaped bcrypt hash of an unguessable, never-configured password,
     * computed via `PASSWORD_DEFAULT` at construction (once per worker boot,
     * never per-request) instead of a hardcoded literal — its cost then
     * always tracks whatever `password_hash($x, PASSWORD_DEFAULT)` actually
     * produces on THIS PHP installation. A hardcoded dummy risks silently
     * drifting from real users' hash cost as PHP's bcrypt default changes
     * across versions/builds, reopening a narrower cost-differential timing
     * gap between "unknown user" and "known, hash-configured user".
     */
    private string $dummyHash;

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
    ) {
        $this->dummyHash = password_hash('waffle-timing-safe-dummy', PASSWORD_DEFAULT);
    }

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

        // CWE-208: always run a password-hash-shaped comparison, even for an
        // unknown username, so timing cannot reveal which usernames exist.
        // The known-vs-unknown decision is gated on array_key_exists(), never
        // on short-circuiting matches() away.
        $known = $this->users[$username] ?? $this->dummyHash;
        $isKnownUser = array_key_exists($username, $this->users);
        $matches = $this->matches($known, $password);

        if (!$isKnownUser || !$matches) {
            throw new AuthenticationException('Invalid Basic credentials.');
        }

        try {
            return new UserIdentity(subject: $username, roles: $this->roles);
        } catch (\InvalidArgumentException $e) {
            // Empty username — schema violation surfaces as a 401, never a 500.
            throw new AuthenticationException('Invalid Basic credentials.', previous: $e);
        }
    }

    /**
     * Constant-time credential comparison (hash-aware).
     *
     * Runs BOTH `password_verify()` and `hash_equals()` unconditionally,
     * discarding whichever result doesn't apply — not just an "either/or"
     * branch on $known's shape. A branch that only pays ONE of the two costs
     * is itself a second, narrower timing oracle: a token-configured known
     * user would resolve via the fast `hash_equals()` path while an unknown
     * username or a hash-configured known user resolves via the slow
     * `password_verify()` path, letting an attacker distinguish "this
     * username is token-based" from "unknown, or hash-based" by timing alone.
     * Paying both costs every time removes that branch as a signal.
     */
    private function matches(#[\SensitiveParameter] string $known, #[\SensitiveParameter] string $candidate): bool
    {
        // `password_hash()` outputs always carry a crypt-style `$<id>$` prefix.
        $isHash =
            str_starts_with($known, '$2y$') || str_starts_with($known, '$2a$') || str_starts_with($known, '$argon2');

        $hashResult = password_verify($candidate, $isHash ? $known : $this->dummyHash);
        $tokenResult = hash_equals($isHash ? self::COMPARISON_FILLER : $known, $candidate);

        return $isHash ? $hashResult : $tokenResult;
    }
}
