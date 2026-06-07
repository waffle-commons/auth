<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Jwt\Key;

use Waffle\Commons\Auth\Exception\InvalidTokenException;
use Waffle\Commons\Contracts\Auth\Token\KeyResolverInterface;

/**
 * Static key material (RFC-021 §4.4): a configured shared secret per
 * algorithm — `['HS256' => $secret]`, `['RS256' => $pemPublicKey]`. The
 * `kid` hint is ignored; static deployments pin exactly one key per
 * algorithm.
 */
final readonly class StaticKeyResolver implements KeyResolverInterface
{
    /**
     * @param array<string, string> $keysByAlgorithm Algorithm → key material
     *        (shared secret for HS256, PEM public key for RS256).
     */
    public function __construct(
        #[\SensitiveParameter]
        private array $keysByAlgorithm,
    ) {}

    #[\Override]
    public function resolve(string $algorithm, ?string $keyId = null): string
    {
        $key = $this->keysByAlgorithm[$algorithm] ?? null;
        if ($key === null || $key === '') {
            throw new InvalidTokenException(sprintf('No static key configured for algorithm "%s".', $algorithm));
        }

        return $key;
    }
}
