<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Jwt\Key;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Exception\InvalidTokenException;
use Waffle\Commons\Auth\Exception\MissingAuthSecretException;
use Waffle\Commons\Auth\Jwt\Key\StaticKeyResolver;
use WaffleTests\Commons\Auth\AbstractTestCase;

#[CoversClass(StaticKeyResolver::class)]
final class StaticKeyResolverTest extends AbstractTestCase
{
    /** 32-byte (== Constant::MIN_SECRET_BYTES) HS256 test key material. */
    private static function validHs256Key(): string
    {
        return str_repeat('k', 32);
    }

    public function testResolvesTheConfiguredKeyPerAlgorithm(): void
    {
        $resolver = new StaticKeyResolver(['HS256' => self::validHs256Key()]);

        self::assertSame(self::validHs256Key(), $resolver->resolve('HS256'));
        self::assertSame(self::validHs256Key(), $resolver->resolve('HS256', 'ignored-kid'));
    }

    public function testRejectsUnconfiguredAlgorithms(): void
    {
        $this->expectException(InvalidTokenException::class);
        new StaticKeyResolver(['HS256' => self::validHs256Key()])->resolve('RS256');
    }

    public function testRejectsEmptyConfiguredKeys(): void
    {
        // Empty is a degenerate case of "too short" — caught at construction now.
        $this->expectException(MissingAuthSecretException::class);
        new StaticKeyResolver(['HS256' => '']);
    }

    public function testRejectsHs256KeyShorterThanTheMinimumFloor(): void
    {
        $this->expectException(MissingAuthSecretException::class);
        $this->expectExceptionMessage('weaker than 32 bytes');

        new StaticKeyResolver(['HS256' => 'only-sixteen-by.']);
    }

    public function testMinimumFloorIsScopedToHsAlgorithmsOnly(): void
    {
        // RS256 keys are PEM material, not a raw HMAC secret — a short
        // placeholder must NOT trip the HS*-only length floor.
        $resolver = new StaticKeyResolver(['RS256' => 'short']);

        self::assertSame('short', $resolver->resolve('RS256'));
    }
}
