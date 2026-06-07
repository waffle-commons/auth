<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Identity\UserIdentity;
use Waffle\Commons\Auth\SecurityContext;
use Waffle\Commons\Contracts\Service\ResettableInterface;

#[CoversClass(SecurityContext::class)]
final class SecurityContextTest extends AbstractTestCase
{
    public function testStartsAnonymous(): void
    {
        $context = new SecurityContext();

        self::assertFalse($context->isAuthenticated());
        self::assertNull($context->getIdentity());
        self::assertNull($context->getClientIp());
    }

    public function testAuthenticateStoresIdentityAndClientIp(): void
    {
        $context = new SecurityContext();
        $identity = new UserIdentity(subject: 'user-42', roles: ['ROLE_ADMIN']);

        $context->authenticate($identity, '203.0.113.7');

        self::assertTrue($context->isAuthenticated());
        self::assertSame($identity, $context->getIdentity());
        self::assertSame('203.0.113.7', $context->getClientIp());
    }

    public function testResetClearsAllStateForTheNextWorkerLoop(): void
    {
        $context = new SecurityContext();
        $context->authenticate(new UserIdentity(subject: 'user-42'), '203.0.113.7');

        $context->reset();

        self::assertFalse($context->isAuthenticated());
        self::assertNull($context->getIdentity());
        self::assertNull($context->getClientIp());
    }

    public function testImplementsTheResettableContractForContainerResets(): void
    {
        self::assertInstanceOf(ResettableInterface::class, new SecurityContext());
    }
}
