<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Oauth;

use JsonException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\SimpleCache\CacheInterface;
use Waffle\Commons\Auth\Exception\OauthException;
use Waffle\Commons\Contracts\Auth\Oauth\DiscoveryInterface;
use Waffle\Commons\Contracts\Auth\Oauth\ProviderMetadataInterface;

/**
 * OIDC discovery (RFC-021 §4.5): resolves an issuer into its provider
 * metadata via `/.well-known/openid-configuration`, fetched over PSR-18 and
 * cached in an injected PSR-16 cache (RFC-013) — never in static state.
 */
final readonly class OidcDiscovery implements DiscoveryInterface
{
    public function __construct(
        private ClientInterface $http,
        private RequestFactoryInterface $requests,
        private CacheInterface $cache,
        private int $cacheTtl = 3_600,
    ) {}

    #[\Override]
    public function discover(string $issuer): ProviderMetadataInterface
    {
        $normalizedIssuer = rtrim($issuer, '/');
        $cacheKey = 'waffle.auth.oidc.' . hash('sha256', $normalizedIssuer);

        try {
            $cached = $this->cache->get($cacheKey);
            if (is_array($cached)) {
                /** @var array<string, mixed> $cached */
                return $this->metadataFrom($cached, $normalizedIssuer);
            }

            $document = $this->fetch($normalizedIssuer . '/.well-known/openid-configuration');
            $this->cache->set($cacheKey, $document, $this->cacheTtl);
        } catch (\Psr\SimpleCache\InvalidArgumentException $e) {
            // The key is generated internally (sha256 hex) — a backend that
            // still rejects it is a wiring fault, surfaced fail-closed.
            throw new OauthException('OIDC discovery cache rejected its internally generated key.', previous: $e);
        }

        return $this->metadataFrom($document, $normalizedIssuer);
    }

    /**
     * @return array<string, mixed>
     *
     * @throws OauthException Unreachable or malformed discovery document.
     */
    private function fetch(string $url): array
    {
        try {
            $response = $this->http->sendRequest($this->requests->createRequest('GET', $url));
        } catch (ClientExceptionInterface $e) {
            throw new OauthException('OIDC discovery document is unreachable.', previous: $e);
        }

        if ($response->getStatusCode() !== 200) {
            throw new OauthException(sprintf('OIDC discovery endpoint answered HTTP %d.', $response->getStatusCode()));
        }

        try {
            $document = json_decode((string) $response->getBody(), associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new OauthException('OIDC discovery document is not valid JSON.', previous: $e);
        }

        if (!is_array($document)) {
            throw new OauthException('OIDC discovery document must be a JSON object.');
        }

        /** @var array<string, mixed> $document */
        return $document;
    }

    /**
     * @param array<string, mixed> $document
     *
     * @throws OauthException Missing mandatory members or issuer mismatch.
     */
    private function metadataFrom(array $document, string $expectedIssuer): ProviderMetadata
    {
        $issuer = $document['issuer'] ?? null;
        $authorization = $document['authorization_endpoint'] ?? null;
        $token = $document['token_endpoint'] ?? null;
        $jwks = $document['jwks_uri'] ?? null;
        $userinfo = $document['userinfo_endpoint'] ?? null;

        if (!is_string($issuer) || !is_string($authorization) || !is_string($token)) {
            throw new OauthException('OIDC discovery document is missing mandatory members.');
        }

        // RFC 8414 §3.3: the document's issuer MUST match the requested one.
        if (rtrim($issuer, '/') !== $expectedIssuer) {
            throw new OauthException('OIDC discovery issuer mismatch — possible impersonation.');
        }

        try {
            return new ProviderMetadata(
                issuer: $issuer,
                authorizationEndpoint: $authorization,
                tokenEndpoint: $token,
                jwksUri: is_string($jwks) ? $jwks : null,
                userinfoEndpoint: is_string($userinfo) ? $userinfo : null,
            );
        } catch (\InvalidArgumentException $e) {
            throw new OauthException('OIDC discovery document carries empty mandatory members.', previous: $e);
        }
    }
}
