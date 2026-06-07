<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Jwt;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Codec\Base64Url;
use Waffle\Commons\Auth\Exception\InvalidTokenException;
use Waffle\Commons\Auth\Jwt\JwtParser;
use Waffle\Commons\Auth\Jwt\JwtParts;
use WaffleTests\Commons\Auth\AbstractTestCase;

#[CoversClass(JwtParser::class)]
#[CoversClass(JwtParts::class)]
final class JwtParserTest extends AbstractTestCase
{
    public function testParsesTheThreeSegmentsAndKeepsTheExactSigningInput(): void
    {
        $header = Base64Url::encode('{"alg":"HS256"}');
        $claims = Base64Url::encode('{"sub":"user-42"}');
        $signature = Base64Url::encode('raw-signature');

        $parts = new JwtParser()->parse($header . '.' . $claims . '.' . $signature);

        self::assertSame('HS256', $parts->header['alg'] ?? null);
        self::assertSame('user-42', $parts->claims['sub'] ?? null);
        self::assertSame('raw-signature', $parts->signature);
        self::assertSame($header . '.' . $claims, $parts->signingInput);
    }

    public function testRejectsWrongSegmentCounts(): void
    {
        $this->expectException(InvalidTokenException::class);
        new JwtParser()->parse('a.b');
    }

    public function testRejectsEmptySegments(): void
    {
        $this->expectException(InvalidTokenException::class);
        new JwtParser()->parse('..');
    }

    public function testRejectsNonBase64HeaderSegments(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('header');

        new JwtParser()->parse('!!!.' . Base64Url::encode('{}') . '.' . Base64Url::encode('s'));
    }

    public function testRejectsNonJsonClaimSegments(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('claims');

        new JwtParser()->parse(
            Base64Url::encode('{"alg":"HS256"}') . '.' . Base64Url::encode('not-json') . '.' . Base64Url::encode('s'),
        );
    }

    public function testRejectsScalarJsonSegments(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('object');

        new JwtParser()->parse(
            Base64Url::encode('"scalar"') . '.' . Base64Url::encode('{}') . '.' . Base64Url::encode('s'),
        );
    }

    public function testRejectsNonBase64SignatureSegments(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('signature');

        new JwtParser()->parse(Base64Url::encode('{"alg":"HS256"}') . '.' . Base64Url::encode('{}') . '.!!!');
    }
}
