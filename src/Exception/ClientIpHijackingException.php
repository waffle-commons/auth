<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Exception;

use Waffle\Commons\Contracts\Auth\Exception\ClientIpHijackingExceptionInterface;

/**
 * IP-binding violation (RFC-021 §4.3): the keyed hash of the observed client
 * IP differs from the signed `iph` claim — the assertion is being replayed
 * from a different client. Always HTTP 403.
 */
final class ClientIpHijackingException extends InvalidAssertionException implements
    ClientIpHijackingExceptionInterface {}
