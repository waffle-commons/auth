<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Exception;

use Throwable;
use Waffle\Commons\Contracts\Auth\Exception\AuthenticationExceptionInterface;

/**
 * Invalid inbound credentials (RFC-021 §3.2): a scheme supported the request
 * but rejected what it carried. Fail-closed — never downgraded to anonymous.
 */
class AuthenticationException extends AuthException implements AuthenticationExceptionInterface
{
    public function __construct(string $message, int $code = 401, ?Throwable $previous = null)
    {
        parent::__construct(message: $message, code: $code, previous: $previous);
    }
}
