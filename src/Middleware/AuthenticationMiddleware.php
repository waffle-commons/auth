<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Waffle\Commons\Contracts\Auth\AuthenticationBridgeInterface;
use Waffle\Commons\Contracts\Auth\Constant;
use Waffle\Commons\Contracts\Auth\Exception\AuthenticationExceptionInterface;

/**
 * PSR-15 entry point of the Universal Authentication Bridge (RFC-021 §3.2).
 *
 * Delegates to the bridge:
 *  - no credentials   → anonymous pass-through (authorization still applies);
 *  - valid credentials → identity published as the `_auth_identity` request
 *    attribute (the bridge already filled the SecurityContext);
 *  - invalid credentials → the scheme's exception propagates (401/403) and
 *    the error-handler renders it (fail-closed).
 *
 * Stateless: the middleware holds no per-request state of its own.
 */
final readonly class AuthenticationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private AuthenticationBridgeInterface $bridge,
        private ?LoggerInterface $logger = null,
    ) {}

    /**
     * @throws AuthenticationExceptionInterface Invalid credentials of a
     *         supporting scheme (HTTP 401/403 — rendered by the error-handler).
     */
    #[\Override]
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        try {
            $identity = $this->bridge->authenticate($request);
        } catch (AuthenticationExceptionInterface $e) {
            $this->logger?->warning('Authentication rejected.', [
                'uri' => (string) $request->getUri(),
                'reason' => $e->getMessage(),
            ]);

            throw $e;
        }

        if ($identity !== null) {
            $request = $request->withAttribute(Constant::REQUEST_ATTRIBUTE, $identity);
        }

        return $handler->handle($request);
    }
}
