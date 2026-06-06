<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Authenticator;

use Psr\Http\Message\ServerRequestInterface;
use Waffle\Commons\Contracts\Auth\AuthenticatorInterface;
use Waffle\Commons\Contracts\Auth\Constant;
use Waffle\Commons\Contracts\Auth\Token\TokenValidatorInterface;
use Waffle\Commons\Contracts\Auth\UserIdentityInterface;

/**
 * Inbound JWT bearer scheme (RFC 6750, RFC-021 §4.4): extracts the compact
 * token from `Authorization: Bearer …` and delegates every cryptographic
 * and claim decision to the {@see TokenValidatorInterface}.
 */
final readonly class JwtAuthenticator implements AuthenticatorInterface
{
    public function __construct(
        private TokenValidatorInterface $validator,
    ) {}

    #[\Override]
    public function supports(ServerRequestInterface $request): bool
    {
        return str_starts_with($request->getHeaderLine(Constant::AUTHORIZATION_HEADER), Constant::BEARER_PREFIX);
    }

    #[\Override]
    public function authenticate(ServerRequestInterface $request): UserIdentityInterface
    {
        $token = substr($request->getHeaderLine(Constant::AUTHORIZATION_HEADER), strlen(Constant::BEARER_PREFIX));

        return $this->validator->validate($token);
    }
}
