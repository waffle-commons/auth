<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Helper;

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/** PSR-18 spy: records every sent request, replays queued responses. */
final class FakeHttpClient implements ClientInterface
{
    /** @var list<RequestInterface> */
    public array $sent = [];

    /** @var list<ResponseInterface> */
    private array $queue = [];

    public function queue(ResponseInterface $response): void
    {
        $this->queue[] = $response;
    }

    #[\Override]
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->sent[] = $request;

        $next = array_shift($this->queue);

        return $next ?? new FakeResponse(200, '{}');
    }
}
