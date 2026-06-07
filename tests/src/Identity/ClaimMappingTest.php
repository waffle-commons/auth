<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Identity;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Identity\ClaimMapping;
use WaffleTests\Commons\Auth\AbstractTestCase;

#[CoversClass(ClaimMapping::class)]
final class ClaimMappingTest extends AbstractTestCase
{
    public function testMapsDefaultOidcClaims(): void
    {
        $identity = new ClaimMapping()->identityFrom([
            'sub' => 'user-42',
            'email' => 'ada@example.test',
            'roles' => ['ROLE_ADMIN', 7, ''],
            'extra' => 'kept',
        ]);

        self::assertSame('user-42', $identity->subject);
        self::assertSame('ada@example.test', $identity->email);
        self::assertSame(['ROLE_ADMIN'], $identity->roles, 'Non-string/empty roles are filtered out.');
        self::assertSame('kept', $identity->claims['extra'] ?? null);
    }

    public function testIntegerSubjectsAreStringified(): void
    {
        $mapping = new ClaimMapping(subject: 'id', email: null, roles: null);

        self::assertSame('12345', $mapping->identityFrom(['id' => 12_345])->subject);
    }

    public function testMissingSubjectClaimIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new ClaimMapping()->identityFrom(['email' => 'ada@example.test']);
    }

    public function testNonStringEmailIsDroppedNotFatal(): void
    {
        $identity = new ClaimMapping()->identityFrom(['sub' => 'user-42', 'email' => 123]);

        self::assertNull($identity->email);
    }

    public function testNullMappingsSkipFields(): void
    {
        $identity = new ClaimMapping(email: null, roles: null)->identityFrom([
            'sub' => 'user-42',
            'email' => 'ignored@example.test',
            'roles' => ['IGNORED'],
        ]);

        self::assertNull($identity->email);
        self::assertSame([], $identity->roles);
    }
}
