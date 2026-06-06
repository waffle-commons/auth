<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Jwt\Key;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Exception\InvalidTokenException;
use Waffle\Commons\Auth\Jwt\Key\StaticKeyResolver;
use WaffleTests\Commons\Auth\AbstractTestCase;

#[CoversClass(StaticKeyResolver::class)]
final class StaticKeyResolverTest extends AbstractTestCase
{
    public function testResolvesTheConfiguredKeyPerAlgorithm(): void
    {
        $resolver = new StaticKeyResolver(['HS256' => 'secret-material']);

        self::assertSame('secret-material', $resolver->resolve('HS256'));
        self::assertSame('secret-material', $resolver->resolve('HS256', 'ignored-kid'));
    }

    public function testRejectsUnconfiguredAlgorithms(): void
    {
        $this->expectException(InvalidTokenException::class);
        new StaticKeyResolver(['HS256' => 'secret'])->resolve('RS256');
    }

    public function testRejectsEmptyConfiguredKeys(): void
    {
        $this->expectException(InvalidTokenException::class);
        new StaticKeyResolver(['HS256' => ''])->resolve('HS256');
    }
}
