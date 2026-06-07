<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Oauth;

use JsonException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Waffle\Commons\Auth\Exception\OauthException;
use Waffle\Commons\Contracts\Auth\Oauth\OauthClientInterface;
use Waffle\Commons\Contracts\Auth\Token\TokenSetInterface;

/**
 * Stateless OAuth2/OIDC relying-party engine (RFC-021 §4.5).
 *
 * Implements the Authorization Code + PKCE (S256 only) and Client
 * Credentials grants over any injected PSR-18 client. The application wires
 * the login/callback routes; this engine never imposes URLs and never
 * stores flow state — `state`/`nonce`/verifier ride the signed transaction
 * cookie ({@see Transaction\OauthTransactionCodec}).
 */
final readonly class OauthClient implements OauthClientInterface
{
    public function __construct(
        private OauthConfig $config,
        private ClientInterface $http,
        private RequestFactoryInterface $requests,
        private StreamFactoryInterface $streams,
    ) {}

    #[\Override]
    public function createAuthorizationUrl(string $state, string $nonce, string $codeChallenge): string
    {
        $query = http_build_query([
            'response_type' => 'code',
            'client_id' => $this->config->clientId,
            'redirect_uri' => $this->config->redirectUri,
            'scope' => implode(' ', $this->config->scopes),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ]);

        $endpoint = $this->config->provider->authorizationEndpoint;
        $separator = str_contains($endpoint, '?') ? '&' : '?';

        return $endpoint . $separator . $query;
    }

    #[\Override]
    public function exchangeCode(string $code, string $codeVerifier): TokenSetInterface
    {
        return $this->requestTokens([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->config->redirectUri,
            'client_id' => $this->config->clientId,
            'client_secret' => $this->config->clientSecret,
            'code_verifier' => $codeVerifier,
        ]);
    }

    #[\Override]
    public function clientCredentials(?string $scope = null): TokenSetInterface
    {
        $parameters = [
            'grant_type' => 'client_credentials',
            'client_id' => $this->config->clientId,
            'client_secret' => $this->config->clientSecret,
        ];

        if ($scope !== null && $scope !== '') {
            $parameters['scope'] = $scope;
        }

        return $this->requestTokens($parameters);
    }

    /**
     * POSTs a form-encoded grant to the token endpoint and decodes the
     * JSON token response (RFC 6749 §5).
     *
     * @param array<string, string> $parameters
     *
     * @throws OauthException Transport failure, provider error response, or
     *         a PSR-17/PSR-7 wiring fault while building the grant request.
     */
    private function requestTokens(#[\SensitiveParameter] array $parameters): TokenSetInterface
    {
        try {
            $request = $this->requests
                ->createRequest('POST', $this->config->provider->tokenEndpoint)
                ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
                ->withHeader('Accept', 'application/json')
                ->withBody($this->streams->createStream(http_build_query($parameters)));
        } catch (\InvalidArgumentException $e) {
            throw new OauthException('OAuth grant request could not be built (PSR-17 wiring fault).', previous: $e);
        }

        try {
            $response = $this->http->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new OauthException('OAuth token endpoint is unreachable.', previous: $e);
        }

        try {
            $data = json_decode((string) $response->getBody(), associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new OauthException('OAuth token response is not valid JSON.', previous: $e);
        }

        if (!is_array($data)) {
            throw new OauthException('OAuth token response must be a JSON object.');
        }

        /** @var array<string, mixed> $data */
        if ($response->getStatusCode() !== 200 || ($data['error'] ?? null) !== null) {
            $error = $data['error'] ?? null;
            throw new OauthException(sprintf(
                'OAuth token endpoint rejected the grant (HTTP %d%s).',
                $response->getStatusCode(),
                is_string($error) ? ', error "' . $error . '"' : '',
            ));
        }

        try {
            return TokenSet::fromTokenResponse($data);
        } catch (\InvalidArgumentException $e) {
            throw new OauthException('OAuth token response is missing a usable access token.', previous: $e);
        }
    }
}
