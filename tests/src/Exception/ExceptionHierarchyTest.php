<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Waffle\Commons\Auth\Exception\AuthenticationException;
use Waffle\Commons\Auth\Exception\AuthException;
use Waffle\Commons\Auth\Exception\ClientIpHijackingException;
use Waffle\Commons\Auth\Exception\ExpiredAssertionException;
use Waffle\Commons\Auth\Exception\InvalidAssertionException;
use Waffle\Commons\Auth\Exception\InvalidTokenException;
use Waffle\Commons\Auth\Exception\MissingAuthSecretException;
use Waffle\Commons\Auth\Exception\OauthException;
use Waffle\Commons\Auth\Exception\SignatureVerificationException;
use Waffle\Commons\Contracts\Auth\Exception\AuthenticationExceptionInterface;
use Waffle\Commons\Contracts\Auth\Exception\AuthExceptionInterface;
use Waffle\Commons\Contracts\Auth\Exception\ClientIpHijackingExceptionInterface;
use Waffle\Commons\Contracts\Auth\Exception\ExpiredAssertionExceptionInterface;
use Waffle\Commons\Contracts\Auth\Exception\InvalidAssertionExceptionInterface;
use Waffle\Commons\Contracts\Auth\Exception\InvalidTokenExceptionInterface;
use Waffle\Commons\Contracts\Auth\Exception\MissingAuthSecretExceptionInterface;
use Waffle\Commons\Contracts\Auth\Exception\OauthExceptionInterface;
use Waffle\Commons\Contracts\Auth\Exception\SignatureVerificationExceptionInterface;
use WaffleTests\Commons\Auth\AbstractTestCase;

/**
 * The exception codes ARE the HTTP statuses the error-handler renders
 * (RFC-021 §5) — this test freezes that contract.
 */
#[CoversClass(AuthException::class)]
#[CoversClass(AuthenticationException::class)]
#[CoversClass(MissingAuthSecretException::class)]
#[CoversClass(InvalidAssertionException::class)]
#[CoversClass(SignatureVerificationException::class)]
#[CoversClass(ExpiredAssertionException::class)]
#[CoversClass(ClientIpHijackingException::class)]
#[CoversClass(InvalidTokenException::class)]
#[CoversClass(OauthException::class)]
final class ExceptionHierarchyTest extends AbstractTestCase
{
    public function testDefaultHttpCodesMatchTheRfcTable(): void
    {
        self::assertSame(500, new AuthException('m')->getCode());
        self::assertSame(401, new AuthenticationException('m')->getCode());
        self::assertSame(500, new MissingAuthSecretException('m')->getCode());
        self::assertSame(403, new InvalidAssertionException('m')->getCode());
        self::assertSame(403, new SignatureVerificationException('m')->getCode());
        self::assertSame(403, new ExpiredAssertionException('m')->getCode());
        self::assertSame(403, new ClientIpHijackingException('m')->getCode());
        self::assertSame(401, new InvalidTokenException('m')->getCode());
        self::assertSame(502, new OauthException('m')->getCode());
    }

    public function testEveryExceptionImplementsItsContractMarker(): void
    {
        self::assertInstanceOf(AuthExceptionInterface::class, new AuthException('m'));
        self::assertInstanceOf(AuthenticationExceptionInterface::class, new AuthenticationException('m'));
        self::assertInstanceOf(MissingAuthSecretExceptionInterface::class, new MissingAuthSecretException('m'));
        self::assertInstanceOf(InvalidAssertionExceptionInterface::class, new InvalidAssertionException('m'));
        self::assertInstanceOf(SignatureVerificationExceptionInterface::class, new SignatureVerificationException('m'));
        self::assertInstanceOf(ExpiredAssertionExceptionInterface::class, new ExpiredAssertionException('m'));
        self::assertInstanceOf(ClientIpHijackingExceptionInterface::class, new ClientIpHijackingException('m'));
        self::assertInstanceOf(InvalidTokenExceptionInterface::class, new InvalidTokenException('m'));
        self::assertInstanceOf(OauthExceptionInterface::class, new OauthException('m'));
    }

    public function testAssertionFailuresNarrowTheBaseMarker(): void
    {
        self::assertInstanceOf(InvalidAssertionExceptionInterface::class, new SignatureVerificationException('m'));
        self::assertInstanceOf(InvalidAssertionExceptionInterface::class, new ExpiredAssertionException('m'));
        self::assertInstanceOf(InvalidAssertionExceptionInterface::class, new ClientIpHijackingException('m'));
        self::assertInstanceOf(AuthenticationExceptionInterface::class, new InvalidAssertionException('m'));
    }
}
