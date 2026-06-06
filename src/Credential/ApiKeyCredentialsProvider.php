<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Credential;

use Psr\Http\Message\RequestInterface;
use Waffle\Commons\Contracts\Auth\Constant;
use Waffle\Commons\Contracts\Auth\CredentialsProviderInterface;

/**
 * Outbound API-key scheme (RFC-021 §4.6/§4.7): attaches the configured key
 * to allow-listed hosts under the configured header (default `X-Api-Key`).
 */
final readonly class ApiKeyCredentialsProvider implements CredentialsProviderInterface
{
    /** @var list<string> Host allow-list, normalized to lowercase. */
    private array $allowedHosts;

    /**
     * @param list<string> $allowedHosts Host allow-list (matched case-insensitively).
     */
    public function __construct(
        #[\SensitiveParameter]
        private string $apiKey,
        array $allowedHosts,
        private string $headerName = Constant::API_KEY_HEADER,
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
        if ($request->hasHeader($this->headerName) || $this->apiKey === '') {
            return $request;
        }

        return $request->withHeader($this->headerName, $this->apiKey);
    }
}
