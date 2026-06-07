<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Credential;

use Psr\Http\Message\RequestInterface;
use Waffle\Commons\Contracts\Auth\Constant;
use Waffle\Commons\Contracts\Auth\CredentialsProviderInterface;

/**
 * Outbound static Bearer scheme (RFC-021 §4.7): attaches a configured
 * long-lived token (PAT, service token) to allow-listed hosts. For
 * provider-issued, expiring tokens use {@see ClientCredentialsProvider}.
 */
final readonly class BearerCredentialsProvider implements CredentialsProviderInterface
{
    /** @var list<string> Host allow-list, normalized to lowercase. */
    private array $allowedHosts;

    /**
     * @param list<string> $allowedHosts Host allow-list (matched case-insensitively).
     */
    public function __construct(
        #[\SensitiveParameter]
        private string $token,
        array $allowedHosts,
    ) {
        $this->allowedHosts = array_values(array_map(strtolower(...), $allowedHosts));
    }

    #[\Override]
    public function supports(RequestInterface $request): bool
    {
        return in_array(strtolower($request->getUri()->getHost()), $this->allowedHosts, true);
    }

    /**
     * @throws \InvalidArgumentException PSR-7 rejected an internally built
     *         header — a wiring fault, never request data.
     */
    #[\Override]
    public function apply(RequestInterface $request): RequestInterface
    {
        if ($request->hasHeader(Constant::AUTHORIZATION_HEADER) || $this->token === '') {
            return $request;
        }

        return $request->withHeader(Constant::AUTHORIZATION_HEADER, Constant::BEARER_PREFIX . $this->token);
    }
}
