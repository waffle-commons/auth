<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Exception;

use Throwable;
use Waffle\Commons\Contracts\Auth\Exception\InvalidAssertionExceptionInterface;

/**
 * Rejected identity assertion (RFC-021 §4.3): malformed wire format,
 * undecodable payload, missing claims, or a temporal window wider than the
 * strict TTL. Always HTTP 403.
 */
class InvalidAssertionException extends AuthenticationException implements InvalidAssertionExceptionInterface
{
    public function __construct(string $message, int $code = 403, ?Throwable $previous = null)
    {
        parent::__construct(message: $message, code: $code, previous: $previous);
    }
}
