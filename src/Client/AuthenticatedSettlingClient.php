<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Client;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Waffle\Commons\Contracts\Auth\CredentialsProviderInterface;
use Waffle\Commons\Contracts\HttpClient\PromiseInterface;
use Waffle\Commons\Contracts\HttpClient\SettlingClientInterface;

/**
 * The outbound credentials decorator (RFC-021 §4.7) over a settling client: like {@see AuthenticatedClient},
 * every supporting provider attaches its credentials to each request, and a batch or a promise stays
 * concurrent below it (RFC-024 §3.3) instead of going one request at a time.
 *
 * Put it under the resilience decorators, as `RetryingClient(CircuitBreakerClient(AuthenticatedSettlingClient(Client)))`,
 * so credentials are applied again on every attempt.
 */
final readonly class AuthenticatedSettlingClient implements ClientInterface, SettlingClientInterface
{
    /**
     * @param ClientInterface&SettlingClientInterface $inner     The decorated transport.
     * @param list<CredentialsProviderInterface>      $providers Outbound schemes, applied in registration order.
     */
    public function __construct(
        private ClientInterface&SettlingClientInterface $inner,
        private array $providers,
    ) {}

    #[\Override]
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        return $this->inner->sendRequest(Credentials::applied($this->providers, $request));
    }

    #[\Override]
    public function sendRequests(array $requests): array
    {
        return $this->inner->sendRequests($this->authenticated($requests));
    }

    #[\Override]
    public function settleRequests(array $requests): array
    {
        return $this->inner->settleRequests($this->authenticated($requests));
    }

    #[\Override]
    public function promise(RequestInterface $request): PromiseInterface
    {
        return $this->inner->promise(Credentials::applied($this->providers, $request));
    }

    /**
     * @param array<array-key, RequestInterface> $requests
     *
     * @return array<array-key, RequestInterface> The same keys, in the same order.
     */
    private function authenticated(array $requests): array
    {
        $authenticated = [];
        foreach ($requests as $key => $request) {
            $authenticated[$key] = Credentials::applied($this->providers, $request);
        }

        return $authenticated;
    }
}
