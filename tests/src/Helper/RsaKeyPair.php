<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Helper;

use OpenSSLAsymmetricKey;

/** Test fixture: an RSA keypair with its JWK members pre-encoded. */
final readonly class RsaKeyPair
{
    public function __construct(
        public OpenSSLAsymmetricKey $privateKey,
        public string $publicPem,
        public string $modulus,
        public string $exponent,
    ) {}
}
