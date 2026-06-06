<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Identity;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Identity\UserIdentity;
use Waffle\Commons\Auth\Uab\UserAssertion;
use Waffle\Commons\Contracts\Auth\Constant;
use WaffleTests\Commons\Auth\AbstractTestCase;

#[CoversClass(UserIdentity::class)]
final class UserIdentityTest extends AbstractTestCase
{
    public function testExposesTheVerifiedIdentityFields(): void
    {
        $identity = new UserIdentity(
            subject: 'user-42',
            email: 'ada@example.test',
            roles: ['ROLE_ADMIN'],
            claims: ['scope' => 'api'],
        );

        self::assertSame('user-42', $identity->subject);
        self::assertSame('ada@example.test', $identity->email);
        self::assertSame(['ROLE_ADMIN'], $identity->roles);
        self::assertSame(['scope' => 'api'], $identity->claims);
    }

    public function testRejectsEmptySubject(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new UserIdentity(subject: '');
    }

    public function testRejectsInvalidEmail(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new UserIdentity(subject: 'user-42', email: 'nope');
    }

    public function testRejectsEmptyRoleStrings(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new UserIdentity(subject: 'user-42', roles: ['ok', '']);
    }

    public function testFromAssertionConvertsSchemaViolationsToAssertionFailures(): void
    {
        $this->expectException(\Waffle\Commons\Auth\Exception\InvalidAssertionException::class);
        $this->expectExceptionCode(403);

        UserIdentity::fromAssertion(new \WaffleTests\Commons\Auth\Helper\SchemaViolatingAssertion());
    }

    public function testFromAssertionMapsClaimsIntoTheBag(): void
    {
        $assertion = new UserAssertion(
            subject: 'user-42',
            email: null,
            roles: ['ROLE_ADMIN'],
            tenant: 'acme',
            issuedAt: 1_000,
            expiresAt: 1_005,
            ipHash: str_repeat('ab', 32),
        );

        $identity = UserIdentity::fromAssertion($assertion);

        self::assertSame('user-42', $identity->subject);
        self::assertNull($identity->email);
        self::assertSame(['ROLE_ADMIN'], $identity->roles);
        self::assertSame('acme', $identity->claims[Constant::CLAIM_TENANT] ?? null);
        self::assertSame(1_000, $identity->claims[Constant::CLAIM_ISSUED_AT] ?? null);
        self::assertSame(1_005, $identity->claims[Constant::CLAIM_EXPIRES_AT] ?? null);
        self::assertSame(str_repeat('ab', 32), $identity->claims[Constant::CLAIM_IP_HASH] ?? null);
    }
}
