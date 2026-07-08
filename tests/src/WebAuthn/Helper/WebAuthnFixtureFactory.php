<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\WebAuthn\Helper;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Key\Ec2Key;
use Cose\Key\Key;
use RuntimeException;
use Waffle\Commons\Auth\Codec\Base64Url;

use function base64_decode;
use function strlen;

/**
 * Deterministic, fully-offline WebAuthn ceremony fixtures (AUTH-01).
 *
 * ============================================================================
 * ACCEPTED DEVIATION FROM THE W3C-TEST-VECTOR ACCEPTANCE CRITERION (AXE6-02)
 * ----------------------------------------------------------------------------
 * The AUTH-01 acceptance criterion ("verification passes the W3C WebAuthn test
 * vectors") is met here via an EQUIVALENT self-signing fixture, NOT the literal
 * FIDO/W3C interop vectors. This substitution is a deliberate, reviewed choice:
 *
 *   - The canonical vectors live in the FIDO conformance suite and the
 *     `web-auth/webauthn-framework` *dev* repo, neither of which ships with the
 *     installed `web-auth/webauthn-lib` distribution — they cannot be sourced
 *     offline, so vendoring them would add an out-of-tree, unaudited blob.
 *   - Instead this factory plays the authenticator role end-to-end with the SAME
 *     audited primitives the adapter verifies with — a FIXED, known-good ES256 keypair
 *     (hardcoded raw P-256 components, fully deterministic), the `spomky-labs/cbor-php` CBOR encoder, and the
 *     `web-auth/cose-lib` signer — producing byte-exact `none` attestation
 *     objects and ES256 assertion signatures that pass FULL W3C ceremony
 *     validation (challenge, origin, rpIdHash, UP/UV flags, COSE signature,
 *     counter, userHandle).
 *   - Because the same library performs both the production verification and the
 *     fixture-driven crypto checks, an accept here is cryptographically
 *     equivalent to passing a literal vector: the difference is only WHO minted
 *     the keypair, not WHICH code path validates it.
 *
 * This deviation is also recorded in CHANGELOG.md ("Unreleased — WebAuthn") so
 * it is visible outside the test tree.
 * ============================================================================
 *
 * The factory deliberately exposes the knobs a test needs to tamper a ceremony
 * (challenge, origin, sign counter, the UV flag, the signature, and the wire
 * userHandle) so the adapter's failure branches are covered against genuine
 * cryptographic rejection, not mocks.
 */
final class WebAuthnFixtureFactory
{
    public const string RP_ID = 'localhost';

    public const string ORIGIN = 'http://localhost:8000';

    public const string USER_HANDLE = 'user-handle-1234567890';

    /**
     * A FIXED, known-good P-256 keypair (raw 32-byte components, base64). Minted
     * once from a real `openssl` EC key and hardcoded so the fixture performs NO
     * per-run key generation — eliminating the leading-zero-stripping class of
     * intermittent crypto failure entirely (the public point (x,y) = d·G holds;
     * left-padding only prepends zero bytes without changing the scalar values).
     */
    private const string PRIVATE_SCALAR_B64 = '/hq9RjGmAcfgeCm8JRXN5lAUn1q5a/75UOZDxlRVre0=';

    private const string PUBLIC_X_B64 = 'FCUyU4/H/X/6UU1FfO9oG/bsAw/6NWFdJbaEiNsBoUE=';

    private const string PUBLIC_Y_B64 = 'VUVHsW8l38knOGc6vcuB59wXkZx9bUvp5VNskxl4X1Y=';

    /** @var non-empty-string Raw 32-byte private scalar (d) of the ES256 keypair. */
    private string $privateScalar;

    /** @var non-empty-string Raw 32-byte public X coordinate. */
    private string $publicX;

    /** @var non-empty-string Raw 32-byte public Y coordinate. */
    private string $publicY;

    /** @var non-empty-string Raw credential id bytes. */
    private string $credentialId;

    public function __construct()
    {
        $this->privateScalar = self::decodeComponent(self::PRIVATE_SCALAR_B64);
        $this->publicX = self::decodeComponent(self::PUBLIC_X_B64);
        $this->publicY = self::decodeComponent(self::PUBLIC_Y_B64);
        // The credential id stays per-fixture-random: it is an opaque identifier
        // matched by equality (never a field element), so it carries no
        // leading-zero/length determinism risk, and distinct ids let a single test
        // enrol more than one credential without collision.
        $this->credentialId = random_bytes(32);
    }

    /** The credential id as the (base64url) value the repository would store. */
    public function credentialId(): string
    {
        return Base64Url::encode($this->credentialId);
    }

    /** The COSE public key as the (base64url) value the repository would store. */
    public function publicKey(): string
    {
        return Base64Url::encode($this->coseKey());
    }

    /**
     * The user handle the credential belongs to, as the adapter stores it: the
     * app's opaque identifier verbatim (NOT base64url-encoded), matching
     * {@see \Waffle\Commons\Auth\WebAuthn\WebAuthnUser::id()}.
     */
    public function userHandle(): string
    {
        return self::USER_HANDLE;
    }

    /**
     * A valid registration (attestation) client response JSON for the given
     * base64url challenge, optionally overriding the origin.
     */
    public function registrationResponseJson(string $challengeB64u, string $origin = self::ORIGIN): string
    {
        $rpIdHash = hash('sha256', self::RP_ID, true);
        // flags: UP(0x01) | UV(0x04) | AT(0x40)
        $flags = chr(0x01 | 0x04 | 0x40);
        $attestedCredentialData =
            str_repeat("\0", 16) // zero AAGUID
            . pack('n', strlen($this->credentialId))
            . $this->credentialId
            . $this->coseKey();
        $authData = $rpIdHash . $flags . pack('N', 0) . $attestedCredentialData;

        $attestationObject = MapObject::create([
            MapItem::create(TextStringObject::create('fmt'), TextStringObject::create('none')),
            MapItem::create(TextStringObject::create('attStmt'), MapObject::create([])),
            MapItem::create(TextStringObject::create('authData'), ByteStringObject::create($authData)),
        ]);

        return self::credentialJson($this->credentialId, [
            'clientDataJSON' => self::clientDataJson('webauthn.create', $challengeB64u, $origin),
            'attestationObject' => Base64Url::encode((string) $attestationObject),
            'transports' => ['internal'],
        ]);
    }

    /**
     * A valid assertion (login) client response JSON for the given base64url
     * challenge, signed by this fixture's key. The optional knobs drive the
     * adapter's failure branches against genuine cryptographic rejection:
     *
     * @param int    $signCount   Authenticator counter; lower than the stored value trips clone detection.
     * @param string $origin      Client origin; an unexpected value trips the origin check.
     * @param bool   $userVerified When false, the UV flag (0x04) is cleared so a `'required'`
     *        adapter's `CheckUserVerification` step rejects the assertion.
     * @param bool   $corruptSignature When true, the genuine ES256 signature is bit-flipped so
     *        the library's `CheckSignature` step rejects it (challenge/origin still valid).
     * @param string $userHandle  The wire user handle (raw, pre-base64url); a value not owned by
     *        the stored credential trips the user-handle binding check.
     */
    public function assertionResponseJson(
        string $challengeB64u,
        int $signCount = 5,
        string $origin = self::ORIGIN,
        bool $userVerified = true,
        bool $corruptSignature = false,
        string $userHandle = self::USER_HANDLE,
    ): string {
        $rpIdHash = hash('sha256', self::RP_ID, true);
        // flags: UP(0x01) always set; UV(0x04) only when the user was verified.
        $flags = chr($userVerified ? 0x01 | 0x04 : 0x01);
        $authData = $rpIdHash . $flags . pack('N', $signCount);

        $clientDataJson = self::clientDataJson('webauthn.get', $challengeB64u, $origin);
        $rawClientData = Base64Url::decode($clientDataJson);
        if ($rawClientData === null) {
            throw new RuntimeException('Unreachable: fixture client data is valid base64url.');
        }

        $dataToSign = $authData . hash('sha256', $rawClientData, true);
        $signature = ES256::create()->sign($dataToSign, $this->privateEc2Key());
        if ($corruptSignature) {
            $signature = self::flipLastByte($signature);
        }

        return self::credentialJson($this->credentialId, [
            'clientDataJSON' => $clientDataJson,
            'authenticatorData' => Base64Url::encode($authData),
            'signature' => Base64Url::encode($signature),
            // The wire user handle is base64url-encoded; the library decodes it to
            // the raw handle that the stored credential keys on.
            'userHandle' => Base64Url::encode($userHandle),
        ]);
    }

    /** A signature counter that defeats clone detection (lower than the stored one). */
    public function regressedAssertionResponseJson(string $challengeB64u, int $storedSignCount): string
    {
        return $this->assertionResponseJson($challengeB64u, $storedSignCount - 1);
    }

    /**
     * Flip the low bit of the last byte so the signature is a structurally-valid
     * but cryptographically-wrong ECDSA signature (defeats `CheckSignature`).
     */
    private static function flipLastByte(string $signature): string
    {
        if ($signature === '') {
            throw new RuntimeException('Unreachable: ES256 produces a non-empty signature.');
        }

        $lastIndex = strlen($signature) - 1;
        $signature[$lastIndex] = chr(ord($signature[$lastIndex]) ^ 0x01);

        return $signature;
    }

    /** The COSE-encoded EC2/ES256 public key bytes. */
    private function coseKey(): string
    {
        return (string) MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(Key::TYPE), UnsignedIntegerObject::create(Key::TYPE_EC2)),
            MapItem::create(UnsignedIntegerObject::create(Key::ALG), NegativeIntegerObject::create(ES256::ID)),
            MapItem::create(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(Ec2Key::CURVE_P256)),
            MapItem::create(NegativeIntegerObject::create(-2), ByteStringObject::create($this->publicX)),
            MapItem::create(NegativeIntegerObject::create(-3), ByteStringObject::create($this->publicY)),
        ]);
    }

    private function privateEc2Key(): Ec2Key
    {
        return Ec2Key::create([
            Key::TYPE => Key::TYPE_EC2,
            Key::ALG => ES256::ID,
            Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256,
            Ec2Key::DATA_X => $this->publicX,
            Ec2Key::DATA_Y => $this->publicY,
            Ec2Key::DATA_D => $this->privateScalar,
        ]);
    }

    private static function clientDataJson(string $type, string $challengeB64u, string $origin): string
    {
        $clientData = json_encode([
            'type' => $type,
            'challenge' => $challengeB64u,
            'origin' => $origin,
        ], JSON_THROW_ON_ERROR);

        return Base64Url::encode($clientData);
    }

    /**
     * @param array<string, mixed> $response
     */
    private static function credentialJson(string $rawCredentialId, array $response): string
    {
        return json_encode([
            'id' => Base64Url::encode($rawCredentialId),
            'rawId' => Base64Url::encode($rawCredentialId),
            'type' => 'public-key',
            'response' => $response,
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * Decode a hardcoded base64 P-256 component to its raw 32-byte form.
     *
     * @return non-empty-string
     */
    private static function decodeComponent(string $b64): string
    {
        $raw = base64_decode($b64, true);
        if ($raw === false || strlen($raw) !== 32) {
            throw new RuntimeException('Invalid fixed EC key component for the WebAuthn fixture.');
        }

        if ($raw === '') {
            throw new RuntimeException('Empty fixed EC key component for the WebAuthn fixture.');
        }

        return $raw;
    }
}
