<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Jwt;

use InvalidArgumentException;
use Waffle\Commons\Auth\Identity\ClaimMapping;

/**
 * Validation policy for inbound bearer tokens (RFC-021 §4.4).
 *
 * The algorithm allow-list is explicit and closed: `none` is rejected at
 * construction time and can never be allow-listed; only `HS256` and `RS256`
 * are supported in Beta 3. Expected `iss` and `aud` are mandatory — a
 * validator without an audience pin does not exist.
 */
final readonly class JwtConfig
{
    /** Algorithms this component implements. */
    private const array SUPPORTED_ALGORITHMS = ['HS256', 'RS256'];

    /**
     * @param list<string> $algorithms Closed allow-list (subset of HS256/RS256).
     * @param string       $issuer     Expected `iss` claim, exact match.
     * @param string       $audience   Expected `aud` claim (string or member
     *                                 of the token's audience list).
     * @param int          $leeway     Clock-skew tolerance in seconds for
     *                                 `exp`/`nbf`/`iat` (0 = strict).
     * @param ClaimMapping $mapping    Claim → identity field mapping.
     *
     * @throws InvalidArgumentException Empty/unsupported allow-list, missing
     *         issuer/audience, or negative leeway.
     */
    public function __construct(
        public array $algorithms,
        public string $issuer,
        public string $audience,
        public int $leeway = 0,
        public ClaimMapping $mapping = new ClaimMapping(),
    ) {
        if ($this->algorithms === []) {
            throw new InvalidArgumentException('JWT algorithm allow-list must not be empty.');
        }

        foreach ($this->algorithms as $algorithm) {
            if (!in_array($algorithm, self::SUPPORTED_ALGORITHMS, true)) {
                throw new InvalidArgumentException(sprintf(
                    'Unsupported JWT algorithm "%s" (supported: %s — "none" is forbidden by design).',
                    $algorithm,
                    implode(', ', self::SUPPORTED_ALGORITHMS),
                ));
            }
        }

        if ($this->issuer === '' || $this->audience === '') {
            throw new InvalidArgumentException('JWT expected issuer and audience are mandatory (RFC-021 §4.4).');
        }

        if ($this->leeway < 0) {
            throw new InvalidArgumentException('JWT leeway must be zero or positive.');
        }
    }
}
