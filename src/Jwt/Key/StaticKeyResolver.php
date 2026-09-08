<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Jwt\Key;

use Waffle\Commons\Auth\Exception\InvalidTokenException;
use Waffle\Commons\Auth\Exception\MissingAuthSecretException;
use Waffle\Commons\Contracts\Auth\Constant;
use Waffle\Commons\Contracts\Auth\Token\KeyResolverInterface;

/**
 * Static key material (RFC-021 §4.4): a configured shared secret per
 * algorithm — `['HS256' => $secret]`, `['RS256' => $pemPublicKey]`. The
 * `kid` hint is ignored; static deployments pin exactly one key per
 * algorithm.
 *
 * Fail-closed boot: an HS-family shared secret shorter than
 * `Constant::MIN_SECRET_BYTES` aborts construction, matching every sibling
 * secret-consumer in this package (`AuthBridgeSigner`, `AuthBridgeVerifier`,
 * `OauthTransactionCodec`). Scoped to HS-family algorithms only — RSA/ECDSA
 * keys are PEM material, not a raw HMAC secret, so the byte floor doesn't
 * apply to them.
 */
final readonly class StaticKeyResolver implements KeyResolverInterface
{
    /**
     * @param array<string, string> $keysByAlgorithm Algorithm → key material
     *        (shared secret for HS256, PEM public key for RS256).
     * @throws MissingAuthSecretException Fail-closed boot when an HS* secret
     *         is missing, empty, or shorter than `Constant::MIN_SECRET_BYTES`.
     */
    public function __construct(
        #[\SensitiveParameter]
        private array $keysByAlgorithm,
    ) {
        foreach ($this->keysByAlgorithm as $algorithm => $key) {
            if (!str_starts_with($algorithm, 'HS')) {
                continue;
            }

            if (strlen($key) < Constant::MIN_SECRET_BYTES) {
                throw new MissingAuthSecretException(sprintf(
                    'The static key for algorithm "%s" is missing or weaker than %d bytes; refusing to initialize the resolver.',
                    $algorithm,
                    Constant::MIN_SECRET_BYTES,
                ));
            }
        }
    }

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
