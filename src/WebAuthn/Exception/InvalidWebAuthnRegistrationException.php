<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\WebAuthn\Exception;

use Throwable;
use Waffle\Commons\Contracts\Auth\WebAuthn\Exception\InvalidWebAuthnRegistrationExceptionInterface;

/**
 * Raised when a WebAuthn attestation (registration) response fails verification
 * (AUTH-01): wrong challenge or origin, a bad attestation signature, or an
 * unsupported attestation format. Fail-closed — the credential is never enrolled.
 * Always HTTP 400 (the client submitted an invalid ceremony response).
 */
final class InvalidWebAuthnRegistrationException extends WebAuthnException implements
    InvalidWebAuthnRegistrationExceptionInterface
{
    public function __construct(string $message, int $code = 400, ?Throwable $previous = null)
    {
        parent::__construct(message: $message, code: $code, previous: $previous);
    }
}
