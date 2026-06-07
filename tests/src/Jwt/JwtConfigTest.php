<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Jwt;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Jwt\JwtConfig;
use WaffleTests\Commons\Auth\AbstractTestCase;

#[CoversClass(JwtConfig::class)]
final class JwtConfigTest extends AbstractTestCase
{
    public function testRejectsEmptyAllowList(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new JwtConfig(algorithms: [], issuer: 'iss', audience: 'aud');
    }

    public function testRejectsNoneEvenWhenExplicitlyAllowListed(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('forbidden');

        new JwtConfig(algorithms: ['none'], issuer: 'iss', audience: 'aud');
    }

    public function testRejectsUnsupportedAlgorithms(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new JwtConfig(algorithms: ['ES256'], issuer: 'iss', audience: 'aud');
    }

    public function testRejectsMissingIssuerOrAudience(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new JwtConfig(algorithms: ['HS256'], issuer: '', audience: 'aud');
    }

    public function testRejectsNegativeLeeway(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new JwtConfig(algorithms: ['HS256'], issuer: 'iss', audience: 'aud', leeway: -1);
    }
}
