<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Uab;

use Waffle\Commons\Auth\Codec\Base64Url;
use Waffle\Commons\Auth\Exception\MissingAuthSecretException;
use Waffle\Commons\Contracts\Auth\Assertion\AssertionSignerInterface;
use Waffle\Commons\Contracts\Auth\Assertion\UserAssertionInterface;
use Waffle\Commons\Contracts\Auth\Constant;

/**
 * Signs Gateway Assertions (RFC-021 §4.3).
 *
 * Wire format: `base64url(canonical JSON payload) . hex(HMAC-SHA256)`,
 * MAC computed over the *encoded* payload with the shared secret
 * (`WAFFLE_AUTH_SECRET`).
 *
 * Fail-closed boot (RFC-021 §4.2): construction aborts with
 * `MissingAuthSecretException` when the secret is missing, empty, or
 * shorter than 32 bytes (256 bits).
 */
final readonly class AuthBridgeSigner implements AssertionSignerInterface
{
    private const string HMAC_ALGO = 'sha256';

    /**
     * @throws MissingAuthSecretException Fail-closed boot (RFC-021 §4.2).
     */
    public function __construct(
        #[\SensitiveParameter]
        private string $secret,
    ) {
        if (strlen($this->secret) < Constant::MIN_SECRET_BYTES) {
            throw new MissingAuthSecretException(sprintf(
                'The %s secret is missing or weaker than %d bytes; refusing to initialize the bridge.',
                Constant::SECRET_ENV_KEY,
                Constant::MIN_SECRET_BYTES,
            ));
        }
    }

    #[\Override]
    public function sign(UserAssertionInterface $assertion): string
    {
        $encodedPayload = Base64Url::encode($assertion->payload);
        $signature = hash_hmac(self::HMAC_ALGO, $encodedPayload, $this->secret);

        return $encodedPayload . '.' . $signature;
    }

    #[\Override]
    public function hashClientIp(string $clientIp): string
    {
        return hash_hmac(self::HMAC_ALGO, $clientIp, $this->secret);
    }
}
