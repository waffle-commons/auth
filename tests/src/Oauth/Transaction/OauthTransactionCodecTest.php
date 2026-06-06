<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Oauth\Transaction;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Exception\MissingAuthSecretException;
use Waffle\Commons\Auth\Exception\OauthException;
use Waffle\Commons\Auth\Oauth\Transaction\OauthTransaction;
use Waffle\Commons\Auth\Oauth\Transaction\OauthTransactionCodec;
use WaffleTests\Commons\Auth\AbstractTestCase;

#[CoversClass(OauthTransactionCodec::class)]
#[CoversClass(OauthTransaction::class)]
final class OauthTransactionCodecTest extends AbstractTestCase
{
    private static function sharedSecret(): string
    {
        return str_repeat('waffle-uab*', 4);
    }

    public function testRoundTripsATransaction(): void
    {
        $codec = new OauthTransactionCodec(self::sharedSecret());
        $transaction = OauthTransaction::start('/dashboard');

        $reopened = $codec->decode($codec->encode($transaction));

        self::assertSame($transaction->state, $reopened->state);
        self::assertSame($transaction->nonce, $reopened->nonce);
        self::assertSame($transaction->codeVerifier, $reopened->codeVerifier);
        self::assertSame('/dashboard', $reopened->returnTo);
    }

    public function testTamperedCookieIsRejected(): void
    {
        $codec = new OauthTransactionCodec(self::sharedSecret());
        $cookie = $codec->encode(OauthTransaction::start());

        $this->expectException(OauthException::class);
        $this->expectExceptionCode(403);

        $codec->decode('A' . substr($cookie, 1));
    }

    public function testExpiredTransactionIsRejected(): void
    {
        $codec = new OauthTransactionCodec(self::sharedSecret(), ttl: 600);
        $cookie = $codec->encode(OauthTransaction::start(), issuedAt: time() - 601);

        $this->expectException(OauthException::class);
        $this->expectExceptionMessage('expired');

        $codec->decode($cookie);
    }

    public function testStructurallyInvalidCookieIsRejected(): void
    {
        $this->expectException(OauthException::class);
        new OauthTransactionCodec(self::sharedSecret())->decode('garbage');
    }

    public function testEmptyCookieSegmentsAreRejected(): void
    {
        $this->expectException(OauthException::class);
        new OauthTransactionCodec(self::sharedSecret())->decode('.');
    }

    public function testValidlySignedNonBase64PayloadIsRejected(): void
    {
        // '!!!' is not base64url, but the MAC over it is valid — the codec
        // must still reject at the decoding stage.
        $cookie = '!!!.' . hash_hmac('sha256', '!!!', self::sharedSecret());

        $this->expectException(OauthException::class);
        $this->expectExceptionMessage('base64url');

        new OauthTransactionCodec(self::sharedSecret())->decode($cookie);
    }

    public function testNonJsonPayloadIsRejected(): void
    {
        $encoded = \Waffle\Commons\Auth\Codec\Base64Url::encode('not json');
        $cookie = $encoded . '.' . hash_hmac('sha256', $encoded, self::sharedSecret());

        $this->expectException(OauthException::class);
        new OauthTransactionCodec(self::sharedSecret())->decode($cookie);
    }

    public function testScalarJsonPayloadIsRejected(): void
    {
        $encoded = \Waffle\Commons\Auth\Codec\Base64Url::encode('"scalar"');
        $cookie = $encoded . '.' . hash_hmac('sha256', $encoded, self::sharedSecret());

        $this->expectException(OauthException::class);
        new OauthTransactionCodec(self::sharedSecret())->decode($cookie);
    }

    public function testMistypedClaimsAreRejected(): void
    {
        $encoded = \Waffle\Commons\Auth\Codec\Base64Url::encode(json_encode([
            'st' => 42,
            'no' => 'n',
            'cv' => 'v',
            'iat' => time(),
        ], flags: JSON_THROW_ON_ERROR));
        $cookie = $encoded . '.' . hash_hmac('sha256', $encoded, self::sharedSecret());

        $this->expectException(OauthException::class);
        $this->expectExceptionMessage('mistyped');

        new OauthTransactionCodec(self::sharedSecret())->decode($cookie);
    }

    public function testEmptyStringClaimsAreRejectedBySchema(): void
    {
        $encoded = \Waffle\Commons\Auth\Codec\Base64Url::encode(json_encode([
            'st' => '',
            'no' => 'n',
            'cv' => 'v',
            'iat' => time(),
        ], flags: JSON_THROW_ON_ERROR));
        $cookie = $encoded . '.' . hash_hmac('sha256', $encoded, self::sharedSecret());

        $this->expectException(OauthException::class);

        new OauthTransactionCodec(self::sharedSecret())->decode($cookie);
    }

    public function testWeakSecretAbortsTheCodecBoot(): void
    {
        $this->expectException(MissingAuthSecretException::class);
        new OauthTransactionCodec('short');
    }

    public function testStartMintsHighEntropyValues(): void
    {
        $first = OauthTransaction::start();
        $second = OauthTransaction::start();

        self::assertNotSame($first->state, $second->state);
        self::assertNotSame($first->nonce, $second->nonce);
        self::assertNotSame($first->codeVerifier, $second->codeVerifier);

        // 16 random bytes ⇒ 32 hex characters (128-bit entropy).
        self::assertSame(32, strlen($first->state));
        self::assertSame(16, strlen((string) hex2bin($first->state)));
    }

    public function testEmptyTransactionValuesAreRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new OauthTransaction(state: '', nonce: 'n', codeVerifier: 'v');
    }
}
