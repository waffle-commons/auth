<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Oauth\Preset;

use Waffle\Commons\Auth\Identity\ClaimMapping;
use Waffle\Commons\Auth\Oauth\ProviderMetadata;

/**
 * Connection presets for popular providers (RFC-021 §4.5) — endpoint
 * metadata plus the claim mapping each provider publishes. Any other OIDC
 * provider works through discovery without a preset; these simply remove
 * the boilerplate for the most common three.
 *
 * GitHub is OAuth2-only (no ID token, no OIDC discovery): identities are
 * resolved through its userinfo API (`/user`), which is why its metadata
 * carries no JWKS URI.
 */
enum ProviderPreset: string
{
    case Google = 'google';
    case Microsoft = 'microsoft';
    case GitHub = 'github';

    /**
     * Static endpoint metadata for the provider.
     *
     * @throws \InvalidArgumentException Unreachable in practice: the preset
     *         endpoints are hardcoded non-empty (declared for `check-throws`).
     */
    public function metadata(): ProviderMetadata
    {
        return match ($this) {
            self::Google => new ProviderMetadata(
                issuer: 'https://accounts.google.com',
                authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
                tokenEndpoint: 'https://oauth2.googleapis.com/token',
                jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
                userinfoEndpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
            ),
            self::Microsoft => new ProviderMetadata(
                issuer: 'https://login.microsoftonline.com/common/v2.0',
                authorizationEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
                tokenEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
                jwksUri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
                userinfoEndpoint: 'https://graph.microsoft.com/oidc/userinfo',
            ),
            self::GitHub => new ProviderMetadata(
                issuer: 'https://github.com',
                authorizationEndpoint: 'https://github.com/login/oauth/authorize',
                tokenEndpoint: 'https://github.com/login/oauth/access_token',
                jwksUri: null,
                userinfoEndpoint: 'https://api.github.com/user',
            ),
        };
    }

    /** Claim mapping published by the provider's tokens / userinfo. */
    public function claimMapping(): ClaimMapping
    {
        return match ($this) {
            self::Google, self::Microsoft => new ClaimMapping(subject: 'sub', email: 'email', roles: 'roles'),
            self::GitHub => new ClaimMapping(subject: 'id', email: 'email', roles: null),
        };
    }

    /**
     * Default scopes appropriate for the provider.
     *
     * @return list<string>
     */
    public function defaultScopes(): array
    {
        return match ($this) {
            self::Google, self::Microsoft => ['openid', 'profile', 'email'],
            self::GitHub => ['read:user', 'user:email'],
        };
    }
}
