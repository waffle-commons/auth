<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Helper;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** PSR-15 handler spy: records the (possibly mutated) forwarded request. */
final class PassHandler implements RequestHandlerInterface
{
    public ?ServerRequestInterface $received = null;

    public function __construct(
        private readonly ResponseInterface $response = new FakeResponse(),
    ) {}

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $this->received = $request;

        return $this->response;
    }
}
