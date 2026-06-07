<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Exception;

use Waffle\Commons\Contracts\Auth\Exception\SignatureVerificationExceptionInterface;

/**
 * Assertion HMAC mismatch under `hash_equals()` (RFC-021 §4.3) — a single
 * mutated character lands here. Always HTTP 403.
 */
final class SignatureVerificationException extends InvalidAssertionException implements
    SignatureVerificationExceptionInterface {}
