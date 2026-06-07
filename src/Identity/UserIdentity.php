<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Identity;

use InvalidArgumentException;
use Waffle\Commons\Auth\Exception\InvalidAssertionException;
use Waffle\Commons\Contracts\Auth\Assertion\UserAssertionInterface;
use Waffle\Commons\Contracts\Auth\Constant;
use Waffle\Commons\Contracts\Auth\UserIdentityInterface;

/**
 * Immutable verified identity (RFC-021 §4.1).
 *
 * PHP 8.5 property hooks enforce the schema at construction time and
 * asymmetric visibility (`private(set)`) freezes every field afterwards —
 * hooked properties cannot be `readonly`, so immutability is provided by
 * the write-once `private(set)` discipline instead.
 */
final class UserIdentity implements UserIdentityInterface
{
    /** Stable unique subject identifier. Never empty. */
    public private(set) string $subject {
        set(string $value) {
            if ($value === '') {
                throw new InvalidArgumentException('Identity subject must not be empty.');
            }
            $this->subject = $value;
        }
    }

    /** Verified email address; when present it must be a valid address. */
    public private(set) ?string $email {
        set(?string $value) {
            if ($value !== null && filter_var($value, FILTER_VALIDATE_EMAIL) === false) {
                throw new InvalidArgumentException('Identity email must be a valid email address.');
            }
            $this->email = $value;
        }
    }

    /**
     * ABAC authorization roles, in declaration order.
     *
     * @var list<string>
     */
    public private(set) array $roles {
        set(array $value) {
            $clean = [];
            foreach ($value as $role) {
                if (!is_string($role) || $role === '') {
                    throw new InvalidArgumentException('Identity roles must be non-empty strings.');
                }
                $clean[] = $role;
            }
            $this->roles = $clean;
        }
    }

    /**
     * Scheme-specific extra claims (token claims, provider profile fields).
     *
     * @var array<string, mixed>
     */
    public private(set) array $claims;

    /**
     * @param list<string>         $roles
     * @param array<string, mixed> $claims
     *
     * @throws InvalidArgumentException Any identity-schema violation.
     */
    public function __construct(string $subject, ?string $email = null, array $roles = [], array $claims = [])
    {
        $this->subject = $subject;
        $this->email = $email;
        $this->roles = $roles;
        $this->claims = $claims;
    }

    /**
     * Maps a verified gateway assertion (RFC-021 §4.3) into an identity.
     * The tenant and temporal claims travel in the claims bag under their
     * compact wire keys.
     *
     * @throws InvalidAssertionException The asserted claims violate the
     *         identity schema (unreachable for verifier-produced assertions).
     */
    public static function fromAssertion(UserAssertionInterface $assertion): self
    {
        try {
            return new self(subject: $assertion->subject, email: $assertion->email, roles: $assertion->roles, claims: [
                Constant::CLAIM_TENANT => $assertion->tenant,
                Constant::CLAIM_ISSUED_AT => $assertion->issuedAt,
                Constant::CLAIM_EXPIRES_AT => $assertion->expiresAt,
                Constant::CLAIM_IP_HASH => $assertion->ipHash,
            ]);
        } catch (InvalidArgumentException $e) {
            throw new InvalidAssertionException('Asserted claims violate the identity schema.', previous: $e);
        }
    }
}
