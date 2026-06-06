<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Oauth\Preset;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Oauth\Preset\ProviderPreset;
use WaffleTests\Commons\Auth\AbstractTestCase;

#[CoversClass(ProviderPreset::class)]
final class ProviderPresetTest extends AbstractTestCase
{
    public function testGoogleIsAFullOidcProvider(): void
    {
        $metadata = ProviderPreset::Google->metadata();

        self::assertSame('https://accounts.google.com', $metadata->issuer);
        self::assertNotNull($metadata->jwksUri);
        self::assertSame('sub', ProviderPreset::Google->claimMapping()->subject);
        self::assertContains('openid', ProviderPreset::Google->defaultScopes());
    }

    public function testMicrosoftIsAFullOidcProvider(): void
    {
        $metadata = ProviderPreset::Microsoft->metadata();

        self::assertStringContainsString('login.microsoftonline.com', $metadata->tokenEndpoint);
        self::assertNotNull($metadata->jwksUri);
    }

    public function testGitHubIsOauth2OnlyWithUserinfoIdentity(): void
    {
        $preset = ProviderPreset::GitHub;
        $metadata = $preset->metadata();

        self::assertNull($metadata->jwksUri, 'GitHub issues no ID tokens — no JWKS.');
        self::assertSame('https://api.github.com/user', $metadata->userinfoEndpoint);
        self::assertSame('id', $preset->claimMapping()->subject);
        self::assertNull($preset->claimMapping()->roles);
        self::assertSame(['read:user', 'user:email'], $preset->defaultScopes());
    }
}
