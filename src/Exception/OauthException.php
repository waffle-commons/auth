<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Exception;

use Throwable;
use Waffle\Commons\Contracts\Auth\Exception\OauthExceptionInterface;

/**
 * OAuth2/OIDC flow failure (RFC-021 §4.5): unreachable or malformed
 * discovery document, provider error at the token endpoint, transaction
 * (`state`/`nonce`/PKCE) violation, or userinfo resolution failure.
 * Defaults to HTTP 502 (upstream provider fault).
 */
final class OauthException extends AuthException implements OauthExceptionInterface
{
    public function __construct(string $message, int $code = 502, ?Throwable $previous = null)
    {
        parent::__construct(message: $message, code: $code, previous: $previous);
    }
}
