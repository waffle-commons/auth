<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Oauth;

use InvalidArgumentException;
use Waffle\Commons\Contracts\Auth\Token\TokenSetInterface;

/**
 * Immutable token material returned by an OAuth2 token endpoint
 * (RFC-021 §4.5). Records its own issuance instant so expiry can be
 * evaluated without ambient state.
 */
final readonly class TokenSet implements TokenSetInterface
{
    public int $issuedAt;

    /**
     * @throws InvalidArgumentException Empty access token.
     */
    public function __construct(
        #[\SensitiveParameter]
        public string $accessToken,
        public string $tokenType = 'Bearer',
        #[\SensitiveParameter]
        public ?string $idToken = null,
        #[\SensitiveParameter]
        public ?string $refreshToken = null,
        public ?int $expiresIn = null,
        public ?string $scope = null,
        ?int $issuedAt = null,
    ) {
        if ($this->accessToken === '') {
            throw new InvalidArgumentException('Token set requires a non-empty access token.');
        }

        $this->issuedAt = $issuedAt ?? time();
    }

    /**
     * Builds the set from a decoded token-endpoint JSON response
     * (RFC 6749 §5.1).
     *
     * @param array<string, mixed> $data
     *
     * @throws InvalidArgumentException Missing/empty access_token member.
     */
    public static function fromTokenResponse(array $data, ?int $issuedAt = null): self
    {
        $accessToken = $data['access_token'] ?? null;
        if (!is_string($accessToken) || $accessToken === '') {
            throw new InvalidArgumentException('Token response is missing its access_token member.');
        }

        $tokenType = $data['token_type'] ?? 'Bearer';
        $idToken = $data['id_token'] ?? null;
        $refreshToken = $data['refresh_token'] ?? null;
        $expiresIn = $data['expires_in'] ?? null;
        $scope = $data['scope'] ?? null;

        return new self(
            accessToken: $accessToken,
            tokenType: is_string($tokenType) ? $tokenType : 'Bearer',
            idToken: is_string($idToken) ? $idToken : null,
            refreshToken: is_string($refreshToken) ? $refreshToken : null,
            expiresIn: is_int($expiresIn) ? $expiresIn : null,
            scope: is_string($scope) ? $scope : null,
            issuedAt: $issuedAt,
        );
    }

    #[\Override]
    public function isExpired(?int $now = null): bool
    {
        if ($this->expiresIn === null) {
            return false;
        }

        return ($now ?? time()) >= ($this->issuedAt + $this->expiresIn);
    }
}
