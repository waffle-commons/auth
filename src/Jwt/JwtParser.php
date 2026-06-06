<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Jwt;

use JsonException;
use Waffle\Commons\Auth\Codec\Base64Url;
use Waffle\Commons\Auth\Exception\InvalidTokenException;

/**
 * Structural JWS compact parser (RFC 7515, RFC-021 §4.4).
 *
 * Splits `header.payload.signature`, strictly base64url-decodes each
 * segment, and JSON-decodes header and claims. NO cryptographic
 * verification happens here — {@see JwtValidator} owns that, and always
 * verifies the signature BEFORE reading any claim.
 */
final readonly class JwtParser
{
    /**
     * @throws InvalidTokenException Structural decode failure (HTTP 401).
     */
    public function parse(#[\SensitiveParameter] string $token): JwtParts
    {
        $segments = explode('.', $token);
        if (count($segments) !== 3 || $segments[0] === '' || $segments[1] === '' || $segments[2] === '') {
            throw new InvalidTokenException('Token is structurally invalid (expected header.payload.signature).');
        }

        [$encodedHeader, $encodedClaims, $encodedSignature] = $segments;

        $header = $this->decodeJsonSegment($encodedHeader, 'header');
        $claims = $this->decodeJsonSegment($encodedClaims, 'claims');

        $signature = Base64Url::decode($encodedSignature);
        if ($signature === null) {
            throw new InvalidTokenException('Token signature segment is not valid base64url.');
        }

        return new JwtParts(
            header: $header,
            claims: $claims,
            signature: $signature,
            signingInput: $encodedHeader . '.' . $encodedClaims,
        );
    }

    /**
     * @return array<string, mixed>
     *
     * @throws InvalidTokenException Malformed base64url/JSON segment.
     */
    private function decodeJsonSegment(string $encoded, string $name): array
    {
        $json = Base64Url::decode($encoded);
        if ($json === null) {
            throw new InvalidTokenException(sprintf('Token %s segment is not valid base64url.', $name));
        }

        try {
            $decoded = json_decode($json, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidTokenException(sprintf('Token %s segment is not valid JSON.', $name), previous: $e);
        }

        if (!is_array($decoded)) {
            throw new InvalidTokenException(sprintf('Token %s segment must decode to a JSON object.', $name));
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }
}
