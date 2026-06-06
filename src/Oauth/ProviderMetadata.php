<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Oauth;

use InvalidArgumentException;
use Waffle\Commons\Contracts\Auth\Oauth\ProviderMetadataInterface;

/**
 * Immutable OAuth2/OIDC provider metadata (RFC-021 §4.5), produced by OIDC
 * discovery or by a shipped {@see ProviderPreset}.
 */
final readonly class ProviderMetadata implements ProviderMetadataInterface
{
    /**
     * @throws InvalidArgumentException Missing mandatory endpoint/issuer.
     */
    public function __construct(
        public string $issuer,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public ?string $jwksUri = null,
        public ?string $userinfoEndpoint = null,
    ) {
        if ($this->issuer === '' || $this->authorizationEndpoint === '' || $this->tokenEndpoint === '') {
            throw new InvalidArgumentException(
                'Provider metadata requires a non-empty issuer, authorization endpoint, and token endpoint.',
            );
        }
    }
}
