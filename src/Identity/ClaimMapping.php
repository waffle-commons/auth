<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Identity;

/**
 * Maps provider-specific claim names onto the portable identity fields
 * (RFC-021 §4.4): which token/profile claims carry the subject, email,
 * roles, and tenant.
 *
 * Null mappings mean "this provider does not publish that field" — the
 * resulting identity simply omits it.
 */
final readonly class ClaimMapping
{
    /**
     * @param string      $subject Claim carrying the unique subject id.
     * @param string|null $email   Claim carrying the email, when published.
     * @param string|null $roles   Claim carrying a list of role strings.
     * @param string|null $tenant  Claim carrying the tenant/organisation id.
     */
    public function __construct(
        public string $subject = 'sub',
        public ?string $email = 'email',
        public ?string $roles = 'roles',
        public ?string $tenant = null,
    ) {}

    /**
     * Builds the identity from a decoded claims payload.
     *
     * @param array<string, mixed> $claims
     *
     * @throws \InvalidArgumentException Missing/mistyped subject claim, or an
     *         identity-schema violation raised by the UserIdentity hooks.
     */
    public function identityFrom(array $claims): UserIdentity
    {
        $subject = $claims[$this->subject] ?? null;
        if (!is_string($subject) && !is_int($subject)) {
            throw new \InvalidArgumentException(sprintf(
                'Claim "%s" (subject) is missing or not a string/int.',
                $this->subject,
            ));
        }

        $email = null;
        if ($this->email !== null) {
            $candidate = $claims[$this->email] ?? null;
            $email = is_string($candidate) && $candidate !== '' ? $candidate : null;
        }

        $roles = [];
        if ($this->roles !== null) {
            $candidate = $claims[$this->roles] ?? null;
            if (is_array($candidate)) {
                foreach ($candidate as $role) {
                    if (!is_string($role) || $role === '') {
                        continue;
                    }

                    $roles[] = $role;
                }
            }
        }

        return new UserIdentity(subject: (string) $subject, email: $email, roles: $roles, claims: $claims);
    }
}
