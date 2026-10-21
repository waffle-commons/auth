<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Client;

use Psr\Http\Message\RequestInterface;
use Waffle\Commons\Contracts\Auth\CredentialsProviderInterface;

/**
 * The outbound credentials step both decorators share (RFC-021 §4.7): every provider that supports the
 * request attaches its credentials, in registration order. Each provider decides applicability itself
 * (`supports()`, host allow-list) and never overwrites an existing header.
 *
 * Pure and stateless.
 */
final class Credentials
{
    /**
     * Sealed: a static-only helper that must never be instantiated.
     *
     * @codeCoverageIgnore
     */
    private function __construct() {}

    /**
     * @param list<CredentialsProviderInterface> $providers
     */
    public static function applied(array $providers, RequestInterface $request): RequestInterface
    {
        foreach ($providers as $provider) {
            if (!$provider->supports($request)) {
                continue;
            }

            $request = $provider->apply($request);
        }

        return $request;
    }
}
