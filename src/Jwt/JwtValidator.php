<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Jwt;

use SensitiveParameter;
use Waffle\Commons\Auth\Exception\InvalidTokenException;
use Waffle\Commons\Contracts\Auth\Token\KeyResolverInterface;
use Waffle\Commons\Contracts\Auth\Token\TokenValidatorInterface;
use Waffle\Commons\Contracts\Auth\UserIdentityInterface;

/**
 * JWS compact token validator (RFC-021 §4.4).
 *
 * Order of operations is a security mandate:
 *   1. structural parse;
 *   2. algorithm allow-list check (`alg: none` rejected unconditionally);
 *   3. key resolution + key/algorithm type consistency (no HS/RS confusion);
 *   4. signature verification (`hash_equals()` for HMAC, `openssl_verify()`
 *      for RSA) — BEFORE any claim is read;
 *   5. claim validation: `exp`, `nbf`, `iat` (bounded leeway), exact `iss`,
 *      `aud` membership, and the OIDC `nonce` when requested.
 */
final readonly class JwtValidator implements TokenValidatorInterface
{
    public function __construct(
        private JwtConfig $config,
        private KeyResolverInterface $keys,
        private JwtParser $parser = new JwtParser(),
    ) {}

    #[\Override]
    public function validate(#[SensitiveParameter] string $token, ?string $expectedNonce = null): UserIdentityInterface
    {
        $parts = $this->parser->parse($token);

        $algorithm = $parts->header['alg'] ?? null;
        if (!is_string($algorithm) || strcasecmp($algorithm, 'none') === 0) {
            throw new InvalidTokenException('Token algorithm is missing or "none" — rejected unconditionally.');
        }

        if (!in_array($algorithm, $this->config->algorithms, true)) {
            throw new InvalidTokenException(sprintf('Token algorithm "%s" is not allow-listed.', $algorithm));
        }

        $keyId = $parts->header['kid'] ?? null;
        $key = $this->keys->resolve($algorithm, is_string($keyId) ? $keyId : null);

        $this->verifySignature($algorithm, $key, $parts);
        $this->verifyTemporalClaims($parts);
        $this->verifyAudienceClaims($parts, $expectedNonce);

        try {
            return $this->config->mapping->identityFrom($parts->claims);
        } catch (\InvalidArgumentException $e) {
            throw new InvalidTokenException('Token claims do not map to a valid identity.', previous: $e);
        }
    }

    /**
     * @throws InvalidTokenException Key/algorithm inconsistency or signature
     *         mismatch (HTTP 401).
     */
    private function verifySignature(string $algorithm, #[SensitiveParameter] string $key, JwtParts $parts): void
    {
        $looksLikePem = str_contains($key, '-----BEGIN');

        if ($algorithm === 'HS256') {
            // Key/algorithm consistency: an RSA public key can never feed the
            // HMAC path (classic HS/RS confusion attack).
            if ($looksLikePem) {
                throw new InvalidTokenException('HS256 requires a shared secret, not a PEM key.');
            }

            $expected = hash_hmac('sha256', $parts->signingInput, $key, binary: true);
            if (!hash_equals($expected, $parts->signature)) {
                throw new InvalidTokenException('Token signature verification failed.');
            }

            return;
        }

        // RS256.
        if (!$looksLikePem) {
            throw new InvalidTokenException('RS256 requires a PEM public key.');
        }

        $publicKey = openssl_pkey_get_public($key);
        if ($publicKey === false) {
            throw new InvalidTokenException('RS256 public key could not be loaded.');
        }

        $result = openssl_verify($parts->signingInput, $parts->signature, $publicKey, OPENSSL_ALGO_SHA256);
        if ($result !== 1) {
            throw new InvalidTokenException('Token signature verification failed.');
        }
    }

    /**
     * @throws InvalidTokenException `exp`/`nbf`/`iat` violation (HTTP 401).
     */
    private function verifyTemporalClaims(JwtParts $parts): void
    {
        $now = time();
        $leeway = $this->config->leeway;

        $expiresAt = $parts->claims['exp'] ?? null;
        if (!is_int($expiresAt)) {
            throw new InvalidTokenException('Token exp claim is missing or mistyped.');
        }
        if (($now - $leeway) >= $expiresAt) {
            throw new InvalidTokenException('Token has expired.');
        }

        $notBefore = $parts->claims['nbf'] ?? null;
        if ($notBefore !== null) {
            if (!is_int($notBefore)) {
                throw new InvalidTokenException('Token nbf claim is mistyped.');
            }
            if (($now + $leeway) < $notBefore) {
                throw new InvalidTokenException('Token is not valid yet (nbf).');
            }
        }

        $issuedAt = $parts->claims['iat'] ?? null;
        if ($issuedAt !== null) {
            if (!is_int($issuedAt)) {
                throw new InvalidTokenException('Token iat claim is mistyped.');
            }
            if ($issuedAt > ($now + $leeway)) {
                throw new InvalidTokenException('Token iat is in the future.');
            }
        }
    }

    /**
     * @throws InvalidTokenException `iss`/`aud`/`nonce` violation (HTTP 401).
     */
    private function verifyAudienceClaims(JwtParts $parts, ?string $expectedNonce): void
    {
        $issuer = $parts->claims['iss'] ?? null;
        if (!is_string($issuer) || $issuer !== $this->config->issuer) {
            throw new InvalidTokenException('Token issuer mismatch.');
        }

        $audience = $parts->claims['aud'] ?? null;
        $audienceList = is_array($audience) ? $audience : [$audience];
        if (!in_array($this->config->audience, $audienceList, true)) {
            throw new InvalidTokenException('Token audience mismatch.');
        }

        if ($expectedNonce !== null) {
            $nonce = $parts->claims['nonce'] ?? null;
            if (!is_string($nonce) || !hash_equals($expectedNonce, $nonce)) {
                throw new InvalidTokenException('Token nonce mismatch (OIDC replay protection).');
            }
        }
    }
}
