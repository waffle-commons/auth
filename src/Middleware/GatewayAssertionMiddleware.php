<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Waffle\Commons\Auth\Authenticator\AssertionAuthenticator;
use Waffle\Commons\Auth\Identity\UserIdentity;
use Waffle\Commons\Contracts\Auth\Assertion\AssertionVerifierInterface;
use Waffle\Commons\Contracts\Auth\Constant;
use Waffle\Commons\Contracts\Auth\SecurityContextInterface;

/**
 * Downstream PSR-15 middleware of the Gateway Assertion Protocol
 * (RFC-021 §4.3): the receiving application's entry firewall.
 *
 * Intercepts `X-Wfl-Assert-User` BEFORE any business controller runs:
 *  - header absent → anonymous pass-through (public routing rules apply);
 *  - valid assertion (signature, temporal window, IP-binding) → the
 *    asserted identity hydrates the SecurityContext and the
 *    `_auth_identity` request attribute — a virtual session boot;
 *  - any violation → the verifier's HTTP-403 exception propagates
 *    (fail-closed; rendered by the error-handler).
 */
final readonly class GatewayAssertionMiddleware implements MiddlewareInterface
{
    public function __construct(
        private AssertionVerifierInterface $verifier,
        private SecurityContextInterface $context,
    ) {}

    /**
     * @throws \Waffle\Commons\Contracts\Auth\Exception\InvalidAssertionExceptionInterface
     *         Tampered signature, temporal violation, or IP-binding mismatch
     *         (HTTP 403 — rendered by the error-handler).
     */
    #[\Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $headerValue = $request->getHeaderLine(Constant::ASSERTION_HEADER);
        if ($headerValue === '') {
            return $handler->handle($request);
        }

        $clientIp = AssertionAuthenticator::remoteAddress($request);
        $assertion = $this->verifier->verify(headerValue: $headerValue, expectedClientIp: $clientIp);

        $identity = UserIdentity::fromAssertion($assertion);
        $this->context->authenticate($identity, $clientIp);

        return $handler->handle($request->withAttribute(Constant::REQUEST_ATTRIBUTE, $identity));
    }
}
