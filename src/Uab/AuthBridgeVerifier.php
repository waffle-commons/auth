<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Uab;

use InvalidArgumentException;
use JsonException;
use Waffle\Commons\Auth\Codec\Base64Url;
use Waffle\Commons\Auth\Exception\ClientIpHijackingException;
use Waffle\Commons\Auth\Exception\ExpiredAssertionException;
use Waffle\Commons\Auth\Exception\InvalidAssertionException;
use Waffle\Commons\Auth\Exception\MissingAuthSecretException;
use Waffle\Commons\Auth\Exception\SignatureVerificationException;
use Waffle\Commons\Contracts\Auth\Assertion\AssertionVerifierInterface;
use Waffle\Commons\Contracts\Auth\Assertion\UserAssertionInterface;
use Waffle\Commons\Contracts\Auth\Constant;

/**
 * Verifies Gateway Assertions (RFC-021 §4.3) — fail-closed.
 *
 * Validation order: structure → signature (`hash_equals()` only) →
 * temporal window (`exp` future, `iat` not future, `exp − iat ≤ 5s`) →
 * keyed IP-binding hash. Every failure throws an HTTP-403 exception; a
 * rejected assertion never degrades into an anonymous request.
 */
final readonly class AuthBridgeVerifier implements AssertionVerifierInterface
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
    public function verify(#[\SensitiveParameter] string $headerValue, string $expectedClientIp): UserAssertionInterface
    {
        $parts = explode('.', $headerValue);
        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new InvalidAssertionException('Assertion is structurally invalid (expected payload.signature).');
        }

        [$encodedPayload, $providedSignature] = $parts;

        $expectedSignature = hash_hmac(self::HMAC_ALGO, $encodedPayload, $this->secret);
        if (!hash_equals($expectedSignature, $providedSignature)) {
            throw new SignatureVerificationException('Assertion signature verification failed.');
        }

        $assertion = $this->decode($encodedPayload);

        $now = time();
        if ($assertion->expiresAt <= $now) {
            throw new ExpiredAssertionException('Assertion has expired (exp is in the past).');
        }

        if ($assertion->issuedAt > $now) {
            throw new ExpiredAssertionException('Assertion iat is in the future.');
        }

        $expectedIpHash = hash_hmac(self::HMAC_ALGO, $expectedClientIp, $this->secret);
        if (!hash_equals($expectedIpHash, $assertion->ipHash)) {
            throw new ClientIpHijackingException('Assertion client-IP binding mismatch (possible hijacking).');
        }

        return $assertion;
    }

    /**
     * Decodes the signed payload into the assertion value object. The VO's
     * property hooks re-validate the claim schema, including the
     * `exp − iat ≤ 5s` window rule.
     *
     * @throws InvalidAssertionException Structural or schema violation (403).
     */
    private function decode(string $encodedPayload): UserAssertion
    {
        $json = Base64Url::decode($encodedPayload);
        if ($json === null) {
            throw new InvalidAssertionException('Assertion payload is not valid base64url.');
        }

        try {
            $claims = json_decode($json, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new InvalidAssertionException('Assertion payload is not valid JSON.', previous: $e);
        }

        if (!is_array($claims)) {
            throw new InvalidAssertionException('Assertion payload must decode to a JSON object.');
        }

        $subject = $claims[Constant::CLAIM_SUBJECT] ?? null;
        $email = $claims[Constant::CLAIM_EMAIL] ?? null;
        $roles = $claims[Constant::CLAIM_ROLES] ?? [];
        $tenant = $claims[Constant::CLAIM_TENANT] ?? null;
        $issuedAt = $claims[Constant::CLAIM_ISSUED_AT] ?? null;
        $expiresAt = $claims[Constant::CLAIM_EXPIRES_AT] ?? null;
        $ipHash = $claims[Constant::CLAIM_IP_HASH] ?? null;

        if (
            !is_string($subject)
            || $email !== null && !is_string($email)
            || !is_array($roles)
            || $tenant !== null && !is_string($tenant)
            || !is_int($issuedAt)
            || !is_int($expiresAt)
            || !is_string($ipHash)
        ) {
            throw new InvalidAssertionException('Assertion payload claims are missing or mistyped.');
        }

        try {
            $stringRoles = [];
            foreach ($roles as $role) {
                if (!is_string($role)) {
                    throw new InvalidAssertionException('Assertion roles (rol) must be strings.');
                }
                $stringRoles[] = $role;
            }

            return new UserAssertion(
                subject: $subject,
                email: $email,
                roles: $stringRoles,
                tenant: $tenant,
                issuedAt: $issuedAt,
                expiresAt: $expiresAt,
                ipHash: $ipHash,
            );
        } catch (InvalidArgumentException $e) {
            throw new InvalidAssertionException(
                'Assertion payload violates the claim schema: ' . $e->getMessage(),
                previous: $e,
            );
        }
    }
}
