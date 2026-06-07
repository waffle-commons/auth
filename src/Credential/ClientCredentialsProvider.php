<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Credential;

use Psr\Http\Message\RequestInterface;
use Psr\SimpleCache\CacheInterface;
use Waffle\Commons\Auth\Exception\OauthException;
use Waffle\Commons\Contracts\Auth\Constant;
use Waffle\Commons\Contracts\Auth\CredentialsProviderInterface;
use Waffle\Commons\Contracts\Auth\Oauth\OauthClientInterface;

/**
 * Outbound OAuth2 Client Credentials scheme (RFC-021 §4.5/§4.7): acquires a
 * service-to-service access token from the provider, caches it in an
 * injected PSR-16 cache (RFC-013) until shortly before expiry, and attaches
 * it as a Bearer header to allow-listed hosts.
 *
 * Stateless by design: the token never lives in a property — the cache is
 * the only storage, shared across worker loops.
 */
final readonly class ClientCredentialsProvider implements CredentialsProviderInterface
{
    /** Safety margin subtracted from the provider lifetime, in seconds. */
    private const int EXPIRY_MARGIN = 30;

    /** @var list<string> Host allow-list, normalized to lowercase. */
    private array $allowedHosts;

    /**
     * @param list<string> $allowedHosts Host allow-list (matched case-insensitively).
     * @param string|null  $scope        Space-separated scopes, when needed.
     */
    public function __construct(
        private OauthClientInterface $oauth,
        private CacheInterface $cache,
        array $allowedHosts,
        private ?string $scope = null,
        private string $cacheKey = 'waffle.auth.client_credentials',
    ) {
        $this->allowedHosts = array_values(array_map(strtolower(...), $allowedHosts));
    }

    #[\Override]
    public function supports(RequestInterface $request): bool
    {
        return in_array(strtolower($request->getUri()->getHost()), $this->allowedHosts, true);
    }

    /**
     * @throws \Waffle\Commons\Contracts\Auth\Exception\OauthExceptionInterface
     *         Grant failure, or a cache backend rejecting the configured key.
     * @throws \InvalidArgumentException PSR-7 rejected an internally built
     *         header — a wiring fault, never request data.
     */
    #[\Override]
    public function apply(RequestInterface $request): RequestInterface
    {
        if ($request->hasHeader(Constant::AUTHORIZATION_HEADER)) {
            return $request;
        }

        return $request->withHeader(Constant::AUTHORIZATION_HEADER, Constant::BEARER_PREFIX . $this->accessToken());
    }

    /**
     * Returns a live access token, from cache or freshly granted.
     *
     * @throws \Waffle\Commons\Contracts\Auth\Exception\OauthExceptionInterface
     */
    private function accessToken(): string
    {
        try {
            $cached = $this->cache->get($this->cacheKey);
            if (is_string($cached) && $cached !== '') {
                return $cached;
            }

            $tokens = $this->oauth->clientCredentials($this->scope);

            $ttl = $tokens->expiresIn !== null ? max(1, $tokens->expiresIn - self::EXPIRY_MARGIN) : null;
            $this->cache->set($this->cacheKey, $tokens->accessToken, $ttl);
        } catch (\Psr\SimpleCache\InvalidArgumentException $e) {
            // The cache key is configuration, not request data — a backend
            // that rejects it is a wiring fault, surfaced fail-closed.
            throw new OauthException('Client-credentials cache rejected its configured key.', previous: $e);
        }

        return $tokens->accessToken;
    }
}
