<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Exception;

use Waffle\Commons\Contracts\Auth\Exception\ExpiredAssertionExceptionInterface;

/**
 * Anti-replay violation (RFC-021 §4.3): the assertion's `exp` is past or its
 * `iat` is in the future. Always HTTP 403.
 */
final class ExpiredAssertionException extends InvalidAssertionException implements ExpiredAssertionExceptionInterface {}
