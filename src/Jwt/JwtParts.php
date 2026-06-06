<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Jwt;

/**
 * The three decoded segments of a JWS compact token (RFC 7515), plus the
 * exact signing input (`header.payload` as received) the signature was
 * computed over. Pure value object produced by {@see JwtParser}.
 */
final readonly class JwtParts
{
    /**
     * @param array<string, mixed> $header    Decoded JOSE header.
     * @param array<string, mixed> $claims    Decoded claims set.
     * @param string               $signature Raw (binary) signature bytes.
     * @param string               $signingInput `base64url(header).base64url(payload)` as received.
     */
    public function __construct(
        public array $header,
        public array $claims,
        public string $signature,
        public string $signingInput,
    ) {}
}
