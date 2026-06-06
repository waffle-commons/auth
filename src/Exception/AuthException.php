<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Exception;

use RuntimeException;
use Throwable;
use Waffle\Commons\Contracts\Auth\Exception\AuthExceptionInterface;

/**
 * Base failure of the Universal Authentication Bridge (RFC-021).
 *
 * The exception code carries the HTTP status so the error-handler's
 * `getCode()` heuristic (RFC-006) renders bridge failures without any
 * auth-specific wiring.
 */
class AuthException extends RuntimeException implements AuthExceptionInterface
{
    public function __construct(string $message, int $code = 500, ?Throwable $previous = null)
    {
        parent::__construct(message: $message, code: $code, previous: $previous);
    }
}
