<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Codec;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Codec\Base64Url;
use WaffleTests\Commons\Auth\AbstractTestCase;

#[CoversClass(Base64Url::class)]
final class Base64UrlTest extends AbstractTestCase
{
    public function testRoundTripsArbitraryBinary(): void
    {
        $binary = random_bytes(64);

        $encoded = Base64Url::encode($binary);

        self::assertMatchesRegularExpression('/^[A-Za-z0-9_\-]+$/', $encoded);
        self::assertSame($binary, Base64Url::decode($encoded));
    }

    public function testEncodesWithoutPaddingAndUrlSafeAlphabet(): void
    {
        // 0xfb 0xff encodes to "+/8=" in standard base64.
        self::assertSame('-_8', Base64Url::encode("\xfb\xff"));
    }

    public function testDecodeRejectsForeignCharactersStrictly(): void
    {
        self::assertNull(Base64Url::decode('not valid base64url!!'));
    }
}
