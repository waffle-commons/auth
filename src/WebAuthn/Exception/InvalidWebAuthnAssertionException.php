<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\WebAuthn\Exception;

use Throwable;
use Waffle\Commons\Contracts\Auth\WebAuthn\Exception\InvalidWebAuthnAssertionExceptionInterface;

/**
 * Raised when a WebAuthn assertion (login) response fails verification (AUTH-01):
 * wrong challenge or origin, a bad signature, an unknown credential, or a
 * non-monotonic signature counter signalling a cloned authenticator.
 *
 * Also an {@see \Waffle\Commons\Contracts\Auth\Exception\AuthenticationExceptionInterface}
 * so the Universal Authentication Bridge treats a failed passkey login as a
 * fail-closed HTTP 401, exactly like any other rejected inbound credential.
 */
final class InvalidWebAuthnAssertionException extends WebAuthnException implements
    InvalidWebAuthnAssertionExceptionInterface
{
    public function __construct(string $message, int $code = 401, ?Throwable $previous = null)
    {
        parent::__construct(message: $message, code: $code, previous: $previous);
    }
}
