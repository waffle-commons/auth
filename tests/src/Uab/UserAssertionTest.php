<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Uab;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Uab\UserAssertion;
use Waffle\Commons\Contracts\Auth\Constant;
use WaffleTests\Commons\Auth\AbstractTestCase;

#[CoversClass(UserAssertion::class)]
final class UserAssertionTest extends AbstractTestCase
{
    private const string IP_HASH = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    public function testPayloadSerializesTheSevenClaimsInCanonicalOrder(): void
    {
        $assertion = self::assertion();

        self::assertSame(
            '{"usr":"user-42","eml":"ada@example.test","rol":["ROLE_ADMIN"],"ten":"acme",'
            . '"iat":1000,"exp":1005,"iph":"'
            . self::IP_HASH
            . '"}',
            $assertion->payload,
        );
    }

    public function testUppercaseIpHashIsNormalizedToLowercase(): void
    {
        $assertion = self::assertion(ipHash: strtoupper(self::IP_HASH));

        self::assertSame(self::IP_HASH, $assertion->ipHash);
    }

    public function testEmptySubjectIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        self::assertion(subject: '');
    }

    public function testInvalidEmailIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        self::assertion(email: 'not-an-email');
    }

    public function testNullEmailIsAccepted(): void
    {
        self::assertNull(self::assertion(email: null)->email);
    }

    public function testEmptyRoleStringIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        self::assertion(roles: ['ROLE_OK', '']);
    }

    public function testEmptyTenantIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        self::assertion(tenant: '');
    }

    public function testMalformedIpHashIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        self::assertion(ipHash: 'zz');
    }

    public function testExpirationBeforeIssuanceIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        self::assertion(issuedAt: 1005, expiresAt: 1000);
    }

    public function testWindowWiderThanTheStrictTtlIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage((string) Constant::ASSERTION_TTL);

        self::assertion(issuedAt: 1000, expiresAt: 1000 + Constant::ASSERTION_TTL + 1);
    }

    public function testNegativeTimestampsAreRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        self::assertion(issuedAt: -1);
    }

    /**
     * @param list<string> $roles
     */
    private static function assertion(
        string $subject = 'user-42',
        ?string $email = 'ada@example.test',
        array $roles = ['ROLE_ADMIN'],
        ?string $tenant = 'acme',
        int $issuedAt = 1_000,
        int $expiresAt = 1_005,
        string $ipHash = self::IP_HASH,
    ): UserAssertion {
        return new UserAssertion(
            subject: $subject,
            email: $email,
            roles: $roles,
            tenant: $tenant,
            issuedAt: $issuedAt,
            expiresAt: $expiresAt,
            ipHash: $ipHash,
        );
    }
}
