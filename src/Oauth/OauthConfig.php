<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Oauth;

use InvalidArgumentException;
use Waffle\Commons\Contracts\Auth\Oauth\ProviderMetadataInterface;

/**
 * Relying-party configuration for one OAuth2/OIDC provider (RFC-021 §4.5):
 * the provider metadata plus this application's client registration.
 */
final readonly class OauthConfig
{
    /**
     * @param list<string> $scopes Requested scopes (space-joined on the wire).
     *
     * @throws InvalidArgumentException Missing client id or redirect URI.
     */
    public function __construct(
        public ProviderMetadataInterface $provider,
        public string $clientId,
        #[\SensitiveParameter]
        public string $clientSecret,
        public string $redirectUri,
        public array $scopes = ['openid', 'profile', 'email'],
    ) {
        if ($this->clientId === '' || $this->redirectUri === '') {
            throw new InvalidArgumentException('OAuth client id and redirect URI are mandatory.');
        }
    }
}
