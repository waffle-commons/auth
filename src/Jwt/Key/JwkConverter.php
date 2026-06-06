<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Jwt\Key;

use Waffle\Commons\Auth\Codec\Base64Url;
use Waffle\Commons\Auth\Exception\InvalidTokenException;

/**
 * Converts an RSA JSON Web Key (`kty: RSA`, RFC 7517) into a PEM
 * SubjectPublicKeyInfo block consumable by `openssl_verify()` — natively,
 * with a minimal DER/ASN.1 builder (Zero-Debt: no third-party JOSE
 * packages).
 *
 * Structure emitted (RFC 3279 / RFC 5280):
 *
 *     SubjectPublicKeyInfo ::= SEQUENCE {
 *         algorithm        SEQUENCE { rsaEncryption OID, NULL },
 *         subjectPublicKey BIT STRING {
 *             RSAPublicKey ::= SEQUENCE { modulus INTEGER, exponent INTEGER }
 *         }
 *     }
 */
final readonly class JwkConverter
{
    /** DER bytes of `SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }` (rsaEncryption). */
    private const string RSA_ALGORITHM_IDENTIFIER = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";

    /**
     * Builds the PEM public key from the JWK `n` (modulus) and `e`
     * (exponent) members.
     *
     * @throws InvalidTokenException Malformed base64url key members.
     */
    public static function rsaToPem(string $modulus, string $exponent): string
    {
        $modulusBytes = Base64Url::decode($modulus);
        $exponentBytes = Base64Url::decode($exponent);
        if ($modulusBytes === null || $modulusBytes === '' || $exponentBytes === null || $exponentBytes === '') {
            throw new InvalidTokenException('JWK RSA members (n/e) are not valid base64url.');
        }

        $rsaPublicKey = self::sequence(self::integer($modulusBytes) . self::integer($exponentBytes));
        $subjectPublicKeyInfo = self::sequence(self::RSA_ALGORITHM_IDENTIFIER . self::bitString($rsaPublicKey));

        return (
            "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n")
            . '-----END PUBLIC KEY-----'
        );
    }

    /** DER INTEGER: big-endian magnitude, 0x00-prefixed when the high bit is set. */
    private static function integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '' || (ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }

        return "\x02" . self::length(strlen($bytes)) . $bytes;
    }

    /** DER BIT STRING with zero unused bits. */
    private static function bitString(string $bytes): string
    {
        return "\x03" . self::length(strlen($bytes) + 1) . "\x00" . $bytes;
    }

    /** DER SEQUENCE. */
    private static function sequence(string $bytes): string
    {
        return "\x30" . self::length(strlen($bytes)) . $bytes;
    }

    /** DER definite-form length octets. */
    private static function length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $octets = '';
        while ($length > 0) {
            $octets = chr($length & 0xff) . $octets;
            $length >>= 8;
        }

        return chr(0x80 | strlen($octets)) . $octets;
    }
}
