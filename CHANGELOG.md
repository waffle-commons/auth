# Changelog — waffle-commons/auth

All notable changes to this component are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Released in lockstep with the Waffle Commons umbrella tag.

## [Unreleased] — targeting `0.1.0-beta3`

**Theme: the Universal Authentication Bridge — every authN scheme, fail-closed, stateless (RFC-021).**

Initial release of the `waffle-commons/auth` component. Owns **all** inbound and
outbound authentication for the ecosystem (the former gateway-specific bridge is
generalised here). Depends only on `waffle-commons/contracts` (+ PSR, PHP core).

### Added
- **SecurityContext** — `final` request-scoped identity holder implementing
  `SecurityContextInterface` + `ResettableInterface`; `reset()` purges the
  authenticated identity and bound client IP between FrankenPHP worker requests.
- **AuthenticationBridge** — orchestrator that walks the configured authenticator
  chain and populates the `SecurityContext`; anonymous when no scheme matches.
- **Inbound authenticators** (one per scheme):
  - `AssertionAuthenticator` — verifies the `X-Wfl-Assert-User` gateway assertion.
  - `JwtAuthenticator` — `Authorization: Bearer` tokens (RS256 + HS256).
  - `ApiKeyAuthenticator` — `X-Api-Key` header matching.
  - `BasicAuthenticator` — HTTP Basic with `password_verify()`.
- **UAB assertion protocol (`X-Wfl-Assert-User`)** — `UserAssertion` immutable
  value object (PHP 8.5 property hooks + asymmetric visibility; compact wire
  claims `usr`/`eml`/`rol`/`ten`/`iat`/`exp`/`iph`), `AuthBridgeSigner`
  (HMAC-SHA256, hex MAC, HMAC-hashed client IP) and `AuthBridgeVerifier`
  (constant-time `hash_equals()` MAC + IP comparison, strict temporal window
  `exp ≤ iat + 5s`). Tamper, expiry, and IP mismatch each raise a dedicated
  `403` exception.
- **OAuth2 / OIDC (stateless)** — `OauthClient` with PKCE (S256),
  `OidcDiscovery` (cached `/.well-known/openid-configuration`),
  `OauthTransactionCodec` (state + nonce carried in a signed cookie — no server
  session), `Pkce`, `TokenSet`, `OauthConfig`, `ProviderMetadata`.
- **JWT engine** — `JwtValidator` (algorithm allowlist, `exp`/`nbf`/`iss`/`aud`
  claim enforcement), `JwtParser` / `JwtParts`, `JwtConfig`, and key resolution
  via static keys or a JWKS endpoint (PSR-16 cached, TTL-bound).
- **Outbound credential providers** (PSR-18 `AuthenticatedClient` decorator):
  `AssertionCredentialsProvider` (host-allowlisted `X-Wfl-Assert-User`
  propagation; never overwrites an existing header; skips anonymous),
  `BearerCredentialsProvider`, `ClientCredentialsProvider`,
  `ApiKeyCredentialsProvider`, `BasicCredentialsProvider`.
- **Middleware** — PSR-15 `AuthenticationMiddleware` (inbound chain entry) and
  `GatewayAssertionMiddleware` (assertion-specific shortcut).
- **Identity** — `UserIdentity`, the concrete `UserIdentityInterface`.
- **Codec** — `Base64Url` (RFC 4648 §5, padding-free).
- **Exceptions** — typed, contracts-backed taxonomy consumed by the RFC 7807
  error handler: `AuthenticationException` / `InvalidTokenException` (`401`),
  `SignatureVerificationException` / `ClientIpHijackingException` /
  `ExpiredAssertionException` / `InvalidAssertionException` (`403`),
  `MissingAuthSecretException` (`500`), `OauthException`, on the `AuthException`
  base — each implementing its `waffle-commons/contracts` marker interface.

### Security
- **Fail-closed boot** — a missing, empty, or short (< 32 bytes)
  `WAFFLE_AUTH_SECRET` aborts the kernel with `MissingAuthSecretException`;
  the bridge never starts in a permissive state.
- **Constant-time everywhere** — every MAC and IP-hash comparison goes through
  `hash_equals()`; no early-return string comparison on secrets.
- **Replay containment** — assertions live at most 5 seconds and are bound to
  the originating client IP (`iph` claim).

### Tests
- Suites covering Authenticator, Credential, Jwt, Oauth, Uab, Identity,
  Exception, Codec (+ shared helpers): chain order, every accept/reject path per
  scheme, signer/verifier round-trips incl. tamper/expiry/IP-mismatch, PKCE and
  discovery caching, JWKS resolution, and the `reset()` purge contract.
- ≥95% line coverage; zero Mago baselines (`composer mago && composer tests`
  green: fmt + lint + analyze + guard + PHPUnit).

### Dependencies
- `php: ^8.5`, `waffle-commons/contracts: self.version`.
