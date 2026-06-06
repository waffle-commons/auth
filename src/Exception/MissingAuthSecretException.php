<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Exception;

use Throwable;
use Waffle\Commons\Contracts\Auth\Exception\MissingAuthSecretExceptionInterface;

/**
 * Fail-closed boot violation (RFC-021 §4.2): a secret-requiring scheme was
 * constructed while `WAFFLE_AUTH_SECRET` was missing, empty, or shorter than
 * 32 bytes (256 bits). Aborts the kernel boot — a misconfigured bridge never
 * degrades into an unauthenticated bypass.
 */
final class MissingAuthSecretException extends AuthException implements MissingAuthSecretExceptionInterface
{
    public function __construct(string $message, int $code = 500, ?Throwable $previous = null)
    {
        parent::__construct(message: $message, code: $code, previous: $previous);
    }
}
