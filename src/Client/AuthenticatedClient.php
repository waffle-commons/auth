<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Client;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Waffle\Commons\Contracts\Auth\CredentialsProviderInterface;

/**
 * Outbound auto-propagation decorator (RFC-021 §4.7): wraps any PSR-18
 * client and lets host-gated {@see CredentialsProviderInterface}s attach
 * credentials (signed assertion, Bearer token, API key, Basic) to outgoing
 * requests before transport.
 *
 * The decorator itself is transport- and scheme-agnostic; each provider
 * decides applicability (`supports()`, host allow-list) and never
 * overwrites an existing header. `waffle-commons/http-client` stays pure
 * transport. Over a settling client, {@see AuthenticatedSettlingClient}
 * keeps batches and promises concurrent.
 */
final readonly class AuthenticatedClient implements ClientInterface
{
    /**
     * @param ClientInterface                    $inner     The decorated transport.
     * @param list<CredentialsProviderInterface> $providers Outbound schemes,
     *        applied in registration order.
     */
    public function __construct(
        private ClientInterface $inner,
        private array $providers,
    ) {}

    #[\Override]
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        return $this->inner->sendRequest(Credentials::applied($this->providers, $request));
    }
}
