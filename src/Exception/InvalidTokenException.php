<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Exception;

use Waffle\Commons\Contracts\Auth\Exception\InvalidTokenExceptionInterface;

/**
 * Bearer-token validation failure (RFC-021 §4.4): structural decode error,
 * `alg: none` or non-allow-listed algorithm, signature mismatch, key
 * resolution failure, or claim violation. Always HTTP 401.
 */
final class InvalidTokenException extends AuthenticationException implements InvalidTokenExceptionInterface {}
