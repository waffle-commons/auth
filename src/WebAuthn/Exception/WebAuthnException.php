<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\WebAuthn\Exception;

use Waffle\Commons\Auth\Exception\AuthException;
use Waffle\Commons\Contracts\Auth\WebAuthn\Exception\WebAuthnExceptionInterface;

/**
 * Base failure of the WebAuthn (passkey) surface (AUTH-01).
 *
 * Sits under the Universal Authentication Bridge's exception tree so a
 * `catch (AuthExceptionInterface)` covers passkey failures alongside JWT, HMAC,
 * and OAuth ones. The HTTP status travels as the exception code.
 */
class WebAuthnException extends AuthException implements WebAuthnExceptionInterface {}
