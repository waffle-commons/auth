<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Helper;

use OpenSSLAsymmetricKey;
use Waffle\Commons\Auth\Codec\Base64Url;

/** Mints real HS256/RS256 compact JWTs for hermetic validator tests. */
final class JwtMinter
{
    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headerExtra
     */
    public static function hs256(#[\SensitiveParameter] string $secret, array $claims, array $headerExtra = []): string
    {
        $signingInput = self::signingInput(['alg' => 'HS256', 'typ' => 'JWT', ...$headerExtra], $claims);

        return $signingInput . '.' . Base64Url::encode(hash_hmac('sha256', $signingInput, $secret, binary: true));
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headerExtra
     */
    public static function rs256(OpenSSLAsymmetricKey $privateKey, array $claims, array $headerExtra = []): string
    {
        $signingInput = self::signingInput(['alg' => 'RS256', 'typ' => 'JWT', ...$headerExtra], $claims);

        $signature = '';
        openssl_sign($signingInput, $signature, $privateKey, OPENSSL_ALGO_SHA256);

        return $signingInput . '.' . Base64Url::encode($signature);
    }

    /**
     * Token with `alg: none` and a decoy signature segment — structurally
     * valid so the rejection MUST come from the algorithm gate.
     *
     * @param array<string, mixed> $claims
     */
    public static function none(array $claims): string
    {
        return self::signingInput(['alg' => 'none', 'typ' => 'JWT'], $claims) . '.' . Base64Url::encode('decoy');
    }

    /** Fresh 2048-bit RSA keypair: [privateKey, publicPem, modulusB64u, exponentB64u]. */
    public static function rsaKeyPair(): RsaKeyPair
    {
        $key = openssl_pkey_new(['private_key_bits' => 2_048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        assert($key !== false);

        $details = openssl_pkey_get_details($key);
        if ($details === false) {
            throw new \RuntimeException('openssl_pkey_get_details() failed for the fixture key.');
        }

        $rsa = $details['rsa'] ?? null;
        $publicPem = $details['key'] ?? null;
        if (!is_array($rsa) || !is_string($publicPem)) {
            throw new \RuntimeException('Fixture key details are missing RSA members.');
        }

        $modulus = $rsa['n'] ?? null;
        $exponent = $rsa['e'] ?? null;
        if (!is_string($modulus) || !is_string($exponent)) {
            throw new \RuntimeException('Fixture key details are missing n/e.');
        }

        return new RsaKeyPair(
            privateKey: $key,
            publicPem: $publicPem,
            modulus: Base64Url::encode($modulus),
            exponent: Base64Url::encode($exponent),
        );
    }

    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $claims
     */
    private static function signingInput(array $header, array $claims): string
    {
        return (
            Base64Url::encode(json_encode($header, flags: JSON_THROW_ON_ERROR))
            . '.'
            . Base64Url::encode(json_encode($claims, flags: JSON_THROW_ON_ERROR))
        );
    }
}
