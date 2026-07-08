<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\WebAuthn;

use Waffle\Commons\Contracts\Auth\WebAuthn\AssertionOptionsInterface;

/**
 * Single-use store for the assertion options issued at the start of a login
 * ceremony (AUTH-01).
 *
 * Like the {@see \Waffle\Commons\Contracts\Auth\WebAuthn\CredentialRepositoryInterface},
 * this is the stateful, app-provided half of the surface: it lives in the
 * application's storage (a cache, session, database, …), NEVER in worker memory,
 * so the {@see WebAuthnAuthenticator} stays stateless across requests. The
 * challenge a login mints is persisted here against an opaque ceremony id and
 * replayed when the browser returns its assertion.
 */
interface WebAuthnChallengeStoreInterface
{
    /**
     * The options issued for the pending login ceremony, or null when the
     * ceremony is unknown or has already been consumed/expired.
     */
    public function take(string $ceremonyId): ?AssertionOptionsInterface;
}
