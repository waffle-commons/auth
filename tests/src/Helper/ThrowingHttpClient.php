<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Helper;

use Exception;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/** PSR-18 fake simulating an unreachable network peer. */
final class ThrowingHttpClient implements ClientInterface
{
    #[\Override]
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        throw new class('network unreachable') extends Exception implements ClientExceptionInterface {};
    }
}
