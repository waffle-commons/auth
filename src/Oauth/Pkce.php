<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Oauth;

use Waffle\Commons\Auth\Codec\Base64Url;

/**
 * PKCE helpers (RFC 7636, RFC-021 §4.5). Only the S256 challenge method is
 * implemented — `plain` is forbidden by design.
 */
final readonly class Pkce
{
    /**
     * Mints a high-entropy code verifier (43 base64url characters).
     *
     * @throws \Random\RandomException The platform CSPRNG is unavailable.
     */
    public static function generateVerifier(): string
    {
        return Base64Url::encode(random_bytes(32));
    }

    /** Derives the S256 challenge: `base64url(sha256(verifier))`. */
    public static function challenge(#[\SensitiveParameter] string $verifier): string
    {
        return Base64Url::encode(hash('sha256', $verifier, binary: true));
    }
}
