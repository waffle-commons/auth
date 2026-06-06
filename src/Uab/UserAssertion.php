<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Uab;

use InvalidArgumentException;
use Waffle\Commons\Contracts\Auth\Assertion\UserAssertionInterface;
use Waffle\Commons\Contracts\Auth\Constant;

/**
 * Immutable Gateway Assertion value object (RFC-021 §4.3).
 *
 * PHP 8.5 property hooks enforce the claim schema at construction time and
 * asymmetric visibility (`private(set)`) freezes every claim afterwards —
 * hooked properties cannot be `readonly`, so immutability is provided by
 * the write-once `private(set)` discipline instead. The virtual `$payload`
 * hook serializes the seven claims into the canonical JSON wire form.
 */
final class UserAssertion implements UserAssertionInterface
{
    /** Unique user (subject) identifier (`usr`). Never empty. */
    public private(set) string $subject {
        set(string $value) {
            if ($value === '') {
                throw new InvalidArgumentException('Assertion subject (usr) must not be empty.');
            }
            $this->subject = $value;
        }
    }

    /** User email address (`eml`); when present it must be a valid address. */
    public private(set) ?string $email {
        set(?string $value) {
            if ($value !== null && filter_var($value, FILTER_VALIDATE_EMAIL) === false) {
                throw new InvalidArgumentException('Assertion email (eml) must be a valid email address.');
            }
            $this->email = $value;
        }
    }

    /**
     * ABAC authorization roles (`rol`), in declaration order.
     *
     * @var list<string>
     */
    public private(set) array $roles {
        set(array $value) {
            $clean = [];
            foreach ($value as $role) {
                if (!is_string($role) || $role === '') {
                    throw new InvalidArgumentException('Assertion roles (rol) must be non-empty strings.');
                }
                $clean[] = $role;
            }
            $this->roles = $clean;
        }
    }

    /** Tenant/organisation id (`ten`); null on single-tenant deployments. */
    public private(set) ?string $tenant {
        set(?string $value) {
            if ($value === '') {
                throw new InvalidArgumentException('Assertion tenant (ten) must be null or non-empty.');
            }
            $this->tenant = $value;
        }
    }

    /** Generation timestamp in Unix seconds (`iat`). */
    public private(set) int $issuedAt {
        set(int $value) {
            if ($value <= 0) {
                throw new InvalidArgumentException('Assertion iat must be a positive Unix timestamp.');
            }
            $this->issuedAt = $value;
        }
    }

    /** Expiry timestamp in Unix seconds (`exp`). */
    public private(set) int $expiresAt {
        set(int $value) {
            if ($value <= 0) {
                throw new InvalidArgumentException('Assertion exp must be a positive Unix timestamp.');
            }
            $this->expiresAt = $value;
        }
    }

    /** Keyed client-IP hash (`iph`): hex HMAC-SHA256 — 64 hex characters. */
    public private(set) string $ipHash {
        set(string $value) {
            if (strlen($value) !== 64 || !ctype_xdigit($value)) {
                throw new InvalidArgumentException('Assertion iph must be a 64-character hex HMAC-SHA256.');
            }
            $this->ipHash = strtolower($value);
        }
    }

    /** Canonical JSON wire payload of the seven claims (`$this->serialize()`). */
    public string $payload {
        get => $this->serialize();
    }

    /**
     * @param list<string> $roles
     *
     * @throws InvalidArgumentException Any claim-schema violation, including
     *         a validity window wider than `Constant::ASSERTION_TTL`.
     */
    public function __construct(
        string $subject,
        ?string $email,
        array $roles,
        ?string $tenant,
        int $issuedAt,
        int $expiresAt,
        string $ipHash,
    ) {
        $this->subject = $subject;
        $this->email = $email;
        $this->roles = $roles;
        $this->tenant = $tenant;
        $this->issuedAt = $issuedAt;
        $this->expiresAt = $expiresAt;
        $this->ipHash = $ipHash;

        if ($expiresAt < $issuedAt) {
            throw new InvalidArgumentException('Assertion exp must not precede iat.');
        }

        if (($expiresAt - $issuedAt) > Constant::ASSERTION_TTL) {
            throw new InvalidArgumentException(sprintf(
                'Assertion validity window must not exceed %d seconds (RFC-021 §4.3).',
                Constant::ASSERTION_TTL,
            ));
        }
    }

    /** Serializes the claims to the canonical JSON wire form (fixed key order). */
    private function serialize(): string
    {
        return json_encode([
            Constant::CLAIM_SUBJECT => $this->subject,
            Constant::CLAIM_EMAIL => $this->email,
            Constant::CLAIM_ROLES => $this->roles,
            Constant::CLAIM_TENANT => $this->tenant,
            Constant::CLAIM_ISSUED_AT => $this->issuedAt,
            Constant::CLAIM_EXPIRES_AT => $this->expiresAt,
            Constant::CLAIM_IP_HASH => $this->ipHash,
        ], flags: JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}
