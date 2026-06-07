<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Oauth\Transaction;

use JsonException;
use Waffle\Commons\Auth\Codec\Base64Url;
use Waffle\Commons\Auth\Exception\MissingAuthSecretException;
use Waffle\Commons\Auth\Exception\OauthException;
use Waffle\Commons\Contracts\Auth\Constant;

/**
 * Signs and re-opens OAuth transactions carried in the `WAFFLE_OAUTH_TX`
 * cookie (RFC-021 §4.5) — the stateless replacement for a server-side
 * session. Wire format mirrors the assertion protocol:
 * `base64url(JSON).hex(HMAC-SHA256)`, with a strict issuance TTL
 * (10 minutes by default) bounding the replay window.
 */
final readonly class OauthTransactionCodec
{
    private const string HMAC_ALGO = 'sha256';

    /**
     * @throws MissingAuthSecretException Fail-closed boot (RFC-021 §4.2).
     */
    public function __construct(
        #[\SensitiveParameter]
        private string $secret,
        private int $ttl = Constant::OAUTH_TRANSACTION_TTL,
    ) {
        if (strlen($this->secret) < Constant::MIN_SECRET_BYTES) {
            throw new MissingAuthSecretException(sprintf(
                'The %s secret is missing or weaker than %d bytes; refusing to initialize the OAuth codec.',
                Constant::SECRET_ENV_KEY,
                Constant::MIN_SECRET_BYTES,
            ));
        }
    }

    /** Serializes and signs the transaction into a cookie-safe value. */
    public function encode(OauthTransaction $transaction, ?int $issuedAt = null): string
    {
        $payload = json_encode([
            'st' => $transaction->state,
            'no' => $transaction->nonce,
            'cv' => $transaction->codeVerifier,
            'rt' => $transaction->returnTo,
            'iat' => $issuedAt ?? time(),
        ], flags: JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        $encoded = Base64Url::encode($payload);

        return $encoded . '.' . hash_hmac(self::HMAC_ALGO, $encoded, $this->secret);
    }

    /**
     * Verifies and re-opens a transaction cookie. Every failure throws —
     * a tampered or stale transaction never silently restarts a login.
     *
     * @throws OauthException Tampered, malformed, or expired transaction (403).
     */
    public function decode(#[\SensitiveParameter] string $cookieValue): OauthTransaction
    {
        $parts = explode('.', $cookieValue);
        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new OauthException('OAuth transaction cookie is structurally invalid.', 403);
        }

        [$encoded, $signature] = $parts;

        $expected = hash_hmac(self::HMAC_ALGO, $encoded, $this->secret);
        if (!hash_equals($expected, $signature)) {
            throw new OauthException('OAuth transaction cookie signature mismatch.', 403);
        }

        $json = Base64Url::decode($encoded);
        if ($json === null) {
            throw new OauthException('OAuth transaction cookie payload is not valid base64url.', 403);
        }

        try {
            $data = json_decode($json, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new OauthException('OAuth transaction cookie payload is not valid JSON.', 403, $e);
        }

        if (!is_array($data)) {
            throw new OauthException('OAuth transaction cookie payload must decode to a JSON object.', 403);
        }

        $state = $data['st'] ?? null;
        $nonce = $data['no'] ?? null;
        $verifier = $data['cv'] ?? null;
        $returnTo = $data['rt'] ?? '/';
        $issuedAt = $data['iat'] ?? null;

        if (!is_string($state) || !is_string($nonce) || !is_string($verifier) || !is_int($issuedAt)) {
            throw new OauthException('OAuth transaction cookie claims are missing or mistyped.', 403);
        }

        if ((time() - $issuedAt) > $this->ttl) {
            throw new OauthException('OAuth transaction has expired; restart the login.', 403);
        }

        try {
            return new OauthTransaction(
                state: $state,
                nonce: $nonce,
                codeVerifier: $verifier,
                returnTo: is_string($returnTo) ? $returnTo : '/',
            );
        } catch (\InvalidArgumentException $e) {
            throw new OauthException('OAuth transaction cookie claims are missing or mistyped.', 403, $e);
        }
    }
}
