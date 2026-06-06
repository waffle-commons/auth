<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Credential;

use Psr\Http\Message\RequestInterface;
use Waffle\Commons\Contracts\Auth\Constant;
use Waffle\Commons\Contracts\Auth\CredentialsProviderInterface;

/**
 * Outbound HTTP Basic scheme (RFC 7617, RFC-021 §4.7): attaches the
 * configured credentials to allow-listed hosts.
 */
final readonly class BasicCredentialsProvider implements CredentialsProviderInterface
{
    /** @var list<string> Host allow-list, normalized to lowercase. */
    private array $allowedHosts;

    /**
     * @param list<string> $allowedHosts Host allow-list (matched case-insensitively).
     */
    public function __construct(
        private string $username,
        #[\SensitiveParameter]
        private string $password,
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
        if ($request->hasHeader(Constant::AUTHORIZATION_HEADER)) {
            return $request;
        }

        $credentials = base64_encode($this->username . ':' . $this->password);

        return $request->withHeader(Constant::AUTHORIZATION_HEADER, Constant::BASIC_PREFIX . $credentials);
    }
}
