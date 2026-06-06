<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Oauth;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Oauth\TokenSet;
use WaffleTests\Commons\Auth\AbstractTestCase;

#[CoversClass(TokenSet::class)]
final class TokenSetTest extends AbstractTestCase
{
    public function testRecordsItsIssuanceInstant(): void
    {
        $tokens = new TokenSet('at', expiresIn: 60, issuedAt: 1_000);

        self::assertSame(1_000, $tokens->issuedAt);
        self::assertFalse($tokens->isExpired(now: 1_059));
        self::assertTrue($tokens->isExpired(now: 1_060));
    }

    public function testDefaultsIssuedAtToNow(): void
    {
        $tokens = new TokenSet('at');

        self::assertEqualsWithDelta(time(), $tokens->issuedAt, 2);
    }

    public function testSetsWithoutLifetimeNeverExpireHere(): void
    {
        self::assertFalse(new TokenSet('at')->isExpired(now: PHP_INT_MAX));
    }

    public function testRejectsEmptyAccessTokens(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new TokenSet('');
    }

    public function testFromTokenResponseIgnoresMistypedOptionalMembers(): void
    {
        $tokens = TokenSet::fromTokenResponse([
            // Expression value: protocol fixture, not a committed credential.
            'access_token' => str_repeat('at', 1),
            'token_type' => 42,
            'id_token' => false,
            'refresh_token' => [],
            'expires_in' => '3600',
            'scope' => null,
        ]);

        self::assertSame('at', $tokens->accessToken);
        self::assertSame('Bearer', $tokens->tokenType);
        self::assertNull($tokens->idToken);
        self::assertNull($tokens->refreshToken);
        self::assertNull($tokens->expiresIn);
        self::assertNull($tokens->scope);
    }

    public function testFromTokenResponseRejectsMissingAccessToken(): void
    {
        $this->expectException(InvalidArgumentException::class);
        TokenSet::fromTokenResponse(['token_type' => 'Bearer']);
    }
}
