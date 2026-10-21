<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Helper;

use LogicException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Waffle\Commons\Contracts\HttpClient\PromiseInterface;
use Waffle\Commons\Contracts\HttpClient\SettlingClientInterface;

/**
 * Settling spy: records every request it receives, alone or in a batch, and the keys of each batch; answers
 * 200 to everything and hands back the promise it was given.
 */
final class FakeSettlingClient implements ClientInterface, SettlingClientInterface
{
    /** @var list<RequestInterface> */
    public array $sent = [];

    /** @var list<list<array-key>> */
    public array $batches = [];

    public function __construct(
        private readonly ?PromiseInterface $promise = null,
    ) {}

    #[\Override]
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->sent[] = $request;

        return new FakeResponse(200, '{}');
    }

    #[\Override]
    public function sendRequests(array $requests): array
    {
        return $this->batch($requests);
    }

    #[\Override]
    public function settleRequests(array $requests): array
    {
        return $this->batch($requests);
    }

    #[\Override]
    public function promise(RequestInterface $request): PromiseInterface
    {
        $this->sent[] = $request;

        return $this->promise ?? throw new LogicException('No promise was scripted.');
    }

    /**
     * @param array<array-key, RequestInterface> $requests
     *
     * @return array<array-key, ResponseInterface>
     */
    private function batch(array $requests): array
    {
        $this->batches[] = array_keys($requests);
        $responses = [];
        foreach ($requests as $key => $request) {
            $this->sent[] = $request;
            $responses[$key] = new FakeResponse(200, '{}');
        }

        return $responses;
    }
}
