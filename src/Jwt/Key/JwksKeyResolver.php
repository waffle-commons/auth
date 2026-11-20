<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Jwt\Key;

use JsonException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\SimpleCache\CacheInterface;
use Waffle\Commons\Auth\Exception\InvalidTokenException;
use Waffle\Commons\Contracts\Auth\Token\KeyResolverInterface;

/**
 * Resolves RS256 verification keys from a provider's JWKS document
 * (RFC-021 §4.4): fetched over PSR-18, selected by `kid`, converted to PEM
 * via {@see JwkConverter}, and cached in an injected PSR-16 cache (RFC-013)
 * with a bounded TTL — never in static state (FrankenPHP rule).
 */
final readonly class JwksKeyResolver implements KeyResolverInterface
{
    public function __construct(
        private string $jwksUri,
        private ClientInterface $http,
        private RequestFactoryInterface $requests,
        private CacheInterface $cache,
        private int $cacheTtl = 3_600,
    ) {}

    #[\Override]
    public function resolve(string $algorithm, ?string $keyId = null): string
    {
        if ($algorithm !== 'RS256') {
            throw new InvalidTokenException(sprintf(
                'JWKS resolution only supports RS256 (got "%s") — shared HMAC secrets never travel in a JWKS.',
                $algorithm,
            ));
        }

        foreach ($this->keys() as $jwk) {
            if (!is_array($jwk) || ($jwk['kty'] ?? null) !== 'RSA') {
                continue;
            }

            $jwkKeyId = $jwk['kid'] ?? null;
            if ($keyId !== null && $jwkKeyId !== $keyId) {
                continue;
            }

            $modulus = $jwk['n'] ?? null;
            $exponent = $jwk['e'] ?? null;
            if (!is_string($modulus) || !is_string($exponent)) {
                continue;
            }

            return JwkConverter::rsaToPem($modulus, $exponent);
        }

        throw new InvalidTokenException(sprintf(
            'No RSA key matches kid "%s" in the JWKS document.',
            $keyId ?? '(none)',
        ));
    }

    /**
     * Returns the JWKS `keys` member, from cache or freshly fetched.
     *
     * @return list<mixed>
     *
     * @throws InvalidTokenException Unreachable/malformed JWKS document, or a
     *         cache backend that rejects the internally generated key.
     */
    private function keys(): array
    {
        $cacheKey = 'waffle.auth.jwks.' . hash('sha256', $this->jwksUri);

        try {
            $cached = $this->cache->get($cacheKey);
            if (is_array($cached)) {
                return array_values($cached);
            }

            $keys = $this->fetch();
            $this->cache->set($cacheKey, $keys, $this->cacheTtl);
        } catch (\Psr\SimpleCache\InvalidArgumentException $e) {
            // The key is generated internally (sha256 hex) — a backend that
            // still rejects it is a wiring fault, surfaced fail-closed.
            throw new InvalidTokenException('JWKS cache rejected its internally generated key.', previous: $e);
        }

        return $keys;
    }

    /**
     * @return list<mixed>
     *
     * @throws InvalidTokenException Unreachable or malformed JWKS document.
     */
    private function fetch(): array
    {
        try {
            $response = $this->http->sendRequest($this->requests->createRequest('GET', $this->jwksUri));
        } catch (ClientExceptionInterface $e) {
            throw new InvalidTokenException('JWKS document is unreachable.', previous: $e);
        }

        if ($response->getStatusCode() !== 200) {
            throw new InvalidTokenException(sprintf('JWKS endpoint answered HTTP %d.', $response->getStatusCode()));
        }

        try {
            $document = json_decode((string) $response->getBody(), associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidTokenException('JWKS document is not valid JSON.', previous: $e);
        }

        if (!is_array($document) || !is_array($document['keys'] ?? null)) {
            throw new InvalidTokenException('JWKS document is missing its "keys" member.');
        }

        return array_values($document['keys']);
    }
}
