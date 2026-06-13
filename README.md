[![Discord](https://img.shields.io/discord/755288001592033391?logo=discord)](https://discord.gg/eKgywnfXr2)
[![PHP Version Require](http://poser.pugx.org/waffle-commons/auth/require/php)](https://packagist.org/packages/waffle-commons/auth)
[![PHP CI](https://github.com/waffle-commons/auth/actions/workflows/main.yml/badge.svg)](https://github.com/waffle-commons/auth/actions/workflows/main.yml)
[![Latest Stable Version](http://poser.pugx.org/waffle-commons/auth/v)](https://packagist.org/packages/waffle-commons/auth)
[![Latest Unstable Version](http://poser.pugx.org/waffle-commons/auth/v/unstable)](https://packagist.org/packages/waffle-commons/auth)
[![Total Downloads](https://img.shields.io/packagist/dt/waffle-commons/auth.svg)](https://packagist.org/packages/waffle-commons/auth)
[![Packagist License](https://img.shields.io/packagist/l/waffle-commons/auth)](https://github.com/waffle-commons/auth/blob/main/LICENSE.md)

Waffle Auth Component
=====================

> **Release:** `0.1.0-beta4` &nbsp;|&nbsp; [`CHANGELOG.md`](./CHANGELOG.md)

The **Universal Authentication Bridge** (UAB, RFC-021): Waffle's entire authentication
layer. Connect a Waffle application to popular authentication services **without technical
debt** — natively, statelessly, fail-closed — in both directions:

- **Inbound** — interchangeable authenticators for OAuth2/OIDC providers (Google,
  Microsoft, Keycloak, Auth0, …), JWT bearer tokens (HS256/RS256 + JWKS), HMAC-signed
  gateway assertions, API keys, and HTTP Basic.
- **Outbound** — a host-gated PSR-18 `AuthenticatedClient` decorator that attaches
  credentials (signed assertion, Bearer token, API key, Basic) to outgoing requests.

Authentication only: *who are you?* Authorization (*may you do this?*) remains in
`waffle-commons/security` (RFC-002 ABAC).

## 📦 Installation

```bash
composer require waffle-commons/auth
```

## 🧱 Surface

| Class | Role |
| :--- | :--- |
| `Waffle\Commons\Auth\SecurityContext` | Request-scoped identity holder. Implements `ResettableInterface` — wiped between FrankenPHP worker loops (zero-leak). |
| `Waffle\Commons\Auth\AuthenticationBridge` | Orchestrator: runs registered authenticators in order; first `supports()` wins; rejection throws (fail-closed); none ⇒ anonymous. |
| `Waffle\Commons\Auth\Middleware\AuthenticationMiddleware` | PSR-15 entry point: bridge + `SecurityContext` + `_auth_identity` request attribute. |
| `Waffle\Commons\Auth\Middleware\GatewayAssertionMiddleware` | Downstream PSR-15 middleware verifying `X-Wfl-Assert-User` (signature, expiry, IP-binding) and hydrating the context. |
| `Waffle\Commons\Auth\Uab\UserAssertion` | Immutable assertion VO (PHP 8.5 hooks + asymmetric visibility): `usr`, `eml`, `rol`, `ten`, `iat`, `exp`, `iph`. |
| `Waffle\Commons\Auth\Uab\AuthBridgeSigner` | Signs assertions: `base64url(payload).hex(HMAC-SHA256)` with `WAFFLE_AUTH_SECRET`. Fail-closed boot (≥ 32-byte secret). |
| `Waffle\Commons\Auth\Uab\AuthBridgeVerifier` | Verifies assertions: `hash_equals()` MAC check, `exp`/`iat` window (≤ 5 s), keyed IP-hash binding. |
| `Waffle\Commons\Auth\Authenticator\JwtAuthenticator` | `Authorization: Bearer` — HS256/RS256, strict alg allow-list, `alg:none` rejected, `iss`/`aud`/`exp`/`nbf` enforced. |
| `Waffle\Commons\Auth\Authenticator\ApiKeyAuthenticator` | `X-Api-Key` — constant-time key matching. |
| `Waffle\Commons\Auth\Authenticator\BasicAuthenticator` | `Authorization: Basic` — `password_verify()` / `hash_equals()`. |
| `Waffle\Commons\Auth\Authenticator\AssertionAuthenticator` | Inbound scheme wrapper around `AuthBridgeVerifier`. |
| `Waffle\Commons\Auth\Oauth\OauthClient` | Authorization-code + PKCE (S256) and client-credentials grants over any PSR-18 client. |
| `Waffle\Commons\Auth\Oauth\OidcDiscovery` | `/.well-known/openid-configuration` resolution, PSR-16 cached. |
| `Waffle\Commons\Auth\Client\AuthenticatedClient` | PSR-18 decorator applying host-gated `CredentialsProviderInterface`s to outgoing requests. |

## 🔐 Security mandates (RFC-021 §5)

- Every MAC/secret comparison uses `hash_equals()` — constant time, zero exceptions.
- **Fail-closed boot:** missing/empty/short (< 32 bytes) `WAFFLE_AUTH_SECRET` ⇒
  `MissingAuthSecretException` aborts the kernel.
- **Anti-replay:** assertions carry `iat`/`exp` with a strict ≤ 5 s window and a keyed
  client-IP hash (`iph`); OAuth `state`/`nonce` ride a signed, short-TTL cookie.
- **Stateless:** no `$_SESSION`, no superglobals, no static state; the `SecurityContext`
  resets every worker loop; `igor-php` green.

## ✅ Quality gates

```bash
composer mago   # fmt + lint + analyze + guard — zero baselines
composer tests  # PHPUnit 12, ≥ 95% coverage
composer igor   # zero state-mutation errors (FrankenPHP)
```

## 📚 Documentation

- RFC-021 — Universal Authentication Bridge (monorepo `project_system/RFCs/`).
- Framework user docs: `documentation/how-to/authentication.md`,
  `documentation/reference/auth.md`,
  `documentation/explanation/authentication-universal-bridge.md`.
