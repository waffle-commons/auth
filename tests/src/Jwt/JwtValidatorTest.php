<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Jwt;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Exception\InvalidTokenException;
use Waffle\Commons\Auth\Jwt\JwtConfig;
use Waffle\Commons\Auth\Jwt\JwtParser;
use Waffle\Commons\Auth\Jwt\JwtParts;
use Waffle\Commons\Auth\Jwt\JwtValidator;
use Waffle\Commons\Auth\Jwt\Key\StaticKeyResolver;
use WaffleTests\Commons\Auth\AbstractTestCase;
use WaffleTests\Commons\Auth\Helper\JwtMinter;

#[CoversClass(JwtValidator::class)]
#[CoversClass(JwtConfig::class)]
#[CoversClass(JwtParser::class)]
#[CoversClass(JwtParts::class)]
#[CoversClass(StaticKeyResolver::class)]
final class JwtValidatorTest extends AbstractTestCase
{
    private static function sharedSecret(): string
    {
        return str_repeat('waffle-jwt*', 4);
    }

    private const string ISSUER = 'https://idp.example.test';
    private const string AUDIENCE = 'waffle-app';

    public function testValidHs256TokenAuthenticates(): void
    {
        $token = JwtMinter::hs256(self::sharedSecret(), $this->claims());

        $identity = $this->validator(['HS256'])->validate($token);

        self::assertSame('user-42', $identity->subject);
        self::assertSame('ada@example.test', $identity->email);
        self::assertSame(['ROLE_ADMIN'], $identity->roles);
    }

    public function testValidRs256TokenAuthenticatesAgainstStaticPem(): void
    {
        $pair = JwtMinter::rsaKeyPair();
        $token = JwtMinter::rs256($pair->privateKey, $this->claims());

        $validator = new JwtValidator(config: $this->config(['RS256']), keys: new StaticKeyResolver([
            'RS256' => $pair->publicPem,
        ]));

        self::assertSame('user-42', $validator->validate($token)->subject);
    }

    public function testAlgNoneIsRejectedUnconditionally(): void
    {
        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('none');

        $this->validator(['HS256'])->validate(JwtMinter::none($this->claims()));
    }

    public function testNonAllowListedAlgorithmIsRejected(): void
    {
        $token = JwtMinter::rs256(JwtMinter::rsaKeyPair()->privateKey, $this->claims());

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('not allow-listed');

        $this->validator(['HS256'])->validate($token);
    }

    public function testHsRsConfusionIsRejectedByKeyTypeCheck(): void
    {
        // Attacker signs with HMAC using the PUBLIC PEM as the shared secret.
        $pair = JwtMinter::rsaKeyPair();
        $forged = JwtMinter::hs256($pair->publicPem, $this->claims());

        $validator = new JwtValidator(config: $this->config(['HS256', 'RS256']), keys: new StaticKeyResolver([
            'HS256' => $pair->publicPem,
            'RS256' => $pair->publicPem,
        ]));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('shared secret');

        $validator->validate($forged);
    }

    public function testTamperedSignatureIsRejected(): void
    {
        $token = JwtMinter::hs256(self::sharedSecret(), $this->claims());
        $tampered = substr($token, 0, -2) . 'xx';

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('signature');

        $this->validator(['HS256'])->validate($tampered);
    }

    public function testRs256TamperedPayloadIsRejected(): void
    {
        $pair = JwtMinter::rsaKeyPair();
        $token = JwtMinter::rs256($pair->privateKey, $this->claims());
        $segments = explode('.', $token);
        $header = $segments[0];
        $signature = $segments[2] ?? '';
        $forged =
            $header
            . '.'
            . rtrim(
                strtr(
                    base64_encode(json_encode($this->claims(['sub' => 'attacker']), flags: JSON_THROW_ON_ERROR)),
                    '+/',
                    '-_',
                ),
                '=',
            )
            . '.'
            . $signature;

        $validator = new JwtValidator(config: $this->config(['RS256']), keys: new StaticKeyResolver([
            'RS256' => $pair->publicPem,
        ]));

        $this->expectException(InvalidTokenException::class);

        $validator->validate($forged);
    }

    public function testExpiredTokenIsRejected(): void
    {
        $token = JwtMinter::hs256(self::sharedSecret(), $this->claims(['exp' => time() - 10]));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('expired');

        $this->validator(['HS256'])->validate($token);
    }

    public function testMissingExpIsRejected(): void
    {
        $claims = $this->claims();
        unset($claims['exp']);
        $token = JwtMinter::hs256(self::sharedSecret(), $claims);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('exp');

        $this->validator(['HS256'])->validate($token);
    }

    public function testNotYetValidNbfIsRejected(): void
    {
        $token = JwtMinter::hs256(self::sharedSecret(), $this->claims(['nbf' => time() + 60]));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('nbf');

        $this->validator(['HS256'])->validate($token);
    }

    public function testFutureIatIsRejected(): void
    {
        $token = JwtMinter::hs256(self::sharedSecret(), $this->claims(['iat' => time() + 60]));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('iat');

        $this->validator(['HS256'])->validate($token);
    }

    public function testMistypedNbfIsRejected(): void
    {
        $token = JwtMinter::hs256(self::sharedSecret(), $this->claims(['nbf' => 'soon']));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('nbf claim is mistyped');

        $this->validator(['HS256'])->validate($token);
    }

    public function testMistypedIatIsRejected(): void
    {
        $token = JwtMinter::hs256(self::sharedSecret(), $this->claims(['iat' => 'recently']));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('iat claim is mistyped');

        $this->validator(['HS256'])->validate($token);
    }

    public function testLeewayToleratesSmallClockSkew(): void
    {
        $token = JwtMinter::hs256(self::sharedSecret(), $this->claims(['nbf' => time() + 3]));

        $identity = $this->validator(['HS256'], leeway: 10)->validate($token);

        self::assertSame('user-42', $identity->subject);
    }

    public function testWrongIssuerIsRejected(): void
    {
        $token = JwtMinter::hs256(self::sharedSecret(), $this->claims(['iss' => 'https://evil.example.test']));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('issuer');

        $this->validator(['HS256'])->validate($token);
    }

    public function testWrongAudienceIsRejected(): void
    {
        $token = JwtMinter::hs256(self::sharedSecret(), $this->claims(['aud' => 'someone-else']));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('audience');

        $this->validator(['HS256'])->validate($token);
    }

    public function testAudienceListMembershipIsAccepted(): void
    {
        $token = JwtMinter::hs256(self::sharedSecret(), $this->claims(['aud' => ['other', self::AUDIENCE]]));

        self::assertSame('user-42', $this->validator(['HS256'])->validate($token)->subject);
    }

    public function testNonceMismatchIsRejectedWhenExpected(): void
    {
        $token = JwtMinter::hs256(self::sharedSecret(), $this->claims(['nonce' => 'minted-nonce']));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('nonce');

        $this->validator(['HS256'])->validate($token, expectedNonce: 'different-nonce');
    }

    public function testMatchingNonceIsAccepted(): void
    {
        $token = JwtMinter::hs256(self::sharedSecret(), $this->claims(['nonce' => 'minted-nonce']));

        $identity = $this->validator(['HS256'])->validate($token, expectedNonce: 'minted-nonce');

        self::assertSame('user-42', $identity->subject);
    }

    public function testStructurallyBrokenTokenIsRejected(): void
    {
        $this->expectException(InvalidTokenException::class);

        $this->validator(['HS256'])->validate('only.two');
    }

    public function testRs256RequiresAPemKey(): void
    {
        $pair = JwtMinter::rsaKeyPair();
        $token = JwtMinter::rs256($pair->privateKey, $this->claims());

        $validator = new JwtValidator(config: $this->config(['RS256']), keys: new StaticKeyResolver([
            'RS256' => 'not-a-pem-key-at-all',
        ]));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('PEM');

        $validator->validate($token);
    }

    public function testKidHeaderIsForwardedToTheKeyResolver(): void
    {
        $token = JwtMinter::hs256(self::sharedSecret(), $this->claims(), headerExtra: ['kid' => 'primary']);

        self::assertSame('user-42', $this->validator(['HS256'])->validate($token)->subject);
    }

    public function testUnparseablePemIsRejected(): void
    {
        $pair = JwtMinter::rsaKeyPair();
        $token = JwtMinter::rs256($pair->privateKey, $this->claims());

        $validator = new JwtValidator(config: $this->config(['RS256']), keys: new StaticKeyResolver([
            'RS256' => "-----BEGIN PUBLIC KEY-----\ngarbage\n-----END PUBLIC KEY-----",
        ]));

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('loaded');

        $validator->validate($token);
    }

    public function testSubjectlessClaimsAreRejectedAs401(): void
    {
        $claims = $this->claims();
        unset($claims['sub']);
        $token = JwtMinter::hs256(self::sharedSecret(), $claims);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('identity');

        $this->validator(['HS256'])->validate($token);
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private function claims(array $overrides = []): array
    {
        return [
            'sub' => 'user-42',
            'email' => 'ada@example.test',
            'roles' => ['ROLE_ADMIN'],
            'iss' => self::ISSUER,
            'aud' => self::AUDIENCE,
            'exp' => time() + 300,
            'iat' => time(),
            ...$overrides,
        ];
    }

    /**
     * @param list<string> $algorithms
     */
    private function validator(array $algorithms, int $leeway = 0): JwtValidator
    {
        return new JwtValidator(config: $this->config($algorithms, $leeway), keys: new StaticKeyResolver([
            'HS256' => self::sharedSecret(),
        ]));
    }

    /**
     * @param list<string> $algorithms
     */
    private function config(array $algorithms, int $leeway = 0): JwtConfig
    {
        return new JwtConfig(algorithms: $algorithms, issuer: self::ISSUER, audience: self::AUDIENCE, leeway: $leeway);
    }
}
