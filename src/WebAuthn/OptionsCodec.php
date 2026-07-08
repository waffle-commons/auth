<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\WebAuthn;

use JsonException;
use Waffle\Commons\Auth\WebAuthn\Exception\WebAuthnException;

/**
 * Typed boundary around the library-serialized options JSON (AUTH-01).
 *
 * The WebAuthn library serializes options to a JSON object string; this codec is
 * the single place that narrows the untyped `json_decode()` result back into a
 * `array<string, mixed>` for the option DTOs' {@see RegistrationOptions::toArray()}.
 * Options the framework itself produced are always well-formed; a decode failure
 * means the stored JSON was corrupted and is surfaced as a 500 (fail-closed).
 */
final class OptionsCodec
{
    /**
     * @return array<string, mixed>
     *
     * @throws WebAuthnException When the options JSON is not a decodable object.
     */
    public static function decode(string $json): array
    {
        try {
            $decoded = json_decode($json, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new WebAuthnException('WebAuthn options JSON is not valid JSON.', previous: $e);
        }

        if (!is_array($decoded)) {
            throw new WebAuthnException('WebAuthn options JSON must decode to a JSON object.');
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }
}
