<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Jwt\Key;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Exception\InvalidTokenException;
use Waffle\Commons\Auth\Jwt\Key\JwkConverter;
use WaffleTests\Commons\Auth\AbstractTestCase;
use WaffleTests\Commons\Auth\Helper\JwtMinter;

#[CoversClass(JwkConverter::class)]
final class JwkConverterTest extends AbstractTestCase
{
    public function testRebuildsAVerifiablePemFromJwkMembers(): void
    {
        $pair = JwtMinter::rsaKeyPair();

        $pem = JwkConverter::rsaToPem($pair->modulus, $pair->exponent);

        // The DER round-trip must yield the exact same SubjectPublicKeyInfo.
        self::assertSame(preg_replace('/\s+/', '', $pair->publicPem), preg_replace('/\s+/', '', $pem));

        // And openssl must accept it for signature verification.
        $signature = '';
        openssl_sign('payload', $signature, $pair->privateKey, OPENSSL_ALGO_SHA256);
        $publicKey = openssl_pkey_get_public($pem);
        self::assertNotFalse($publicKey);
        self::assertSame(1, openssl_verify('payload', $signature, $publicKey, OPENSSL_ALGO_SHA256));
    }

    public function testRejectsMalformedJwkMembers(): void
    {
        $this->expectException(InvalidTokenException::class);
        JwkConverter::rsaToPem('!!!not-base64url!!!', 'AQAB');
    }
}
