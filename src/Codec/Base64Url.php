<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Codec;

/**
 * Unpadded Base64-URL codec (RFC 4648 §5) shared by the assertion, JWT,
 * and OAuth transaction wire formats. Pure functions — no state.
 */
final readonly class Base64Url
{
    /** Encodes binary data to unpadded base64url. */
    public static function encode(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }

    /**
     * Decodes unpadded base64url; returns null on any malformed input
     * (strict mode — no silent character skipping).
     */
    public static function decode(string $value): ?string
    {
        $padded = strtr($value, '-_', '+/');
        $padLength = (4 - (strlen($padded) % 4)) % 4;
        $padded .= str_repeat('=', $padLength);

        $decoded = base64_decode($padded, strict: true);

        return $decoded === false ? null : $decoded;
    }
}
