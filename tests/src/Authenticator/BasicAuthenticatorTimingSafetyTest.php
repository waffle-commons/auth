<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Authenticator;

use phpmock\phpunit\PHPMock;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Waffle\Commons\Auth\Authenticator\BasicAuthenticator;
use Waffle\Commons\Auth\Exception\AuthenticationException;
use Waffle\Commons\Contracts\Auth\Constant;
use WaffleTests\Commons\Auth\AbstractTestCase;
use WaffleTests\Commons\Auth\Helper\FakeServerRequest;

/**
 * CWE-208 regression, isolated from {@see BasicAuthenticatorTest} because it
 * intercepts `password_verify()` for the whole
 * `Waffle\Commons\Auth\Authenticator` namespace via php-mock — sharing that
 * with tests asserting genuine hash verification would require stubbing every
 * one of them too.
 */
#[CoversClass(BasicAuthenticator::class)]
#[RunTestsInSeparateProcesses]
final class BasicAuthenticatorTimingSafetyTest extends AbstractTestCase
{
    use PHPMock;

    private const string SUBJECT_NAMESPACE = 'Waffle\Commons\Auth\Authenticator';

    #[\Override]
    public static function setUpBeforeClass(): void
    {
        // php-mock: the namespaced fallback must exist before the first
        // unqualified call in the subject namespace, or PHP binds the global
        // for good.
        self::defineFunctionMock(self::SUBJECT_NAMESPACE, 'password_verify');
    }

    public function testUnknownUsernameStillInvokesPasswordVerify(): void
    {
        // The known user's secret is a bcrypt hash, so matches() must route
        // through password_verify() — the dummy-hash comparison used for an
        // UNKNOWN username must exercise that exact same call, not skip it.
        $verify = $this->getFunctionMock(self::SUBJECT_NAMESPACE, 'password_verify');
        $verify->expects(self::once())->willReturn(false);

        $authenticator = new BasicAuthenticator(['ada' => password_hash('s3cret', PASSWORD_BCRYPT)]);

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($this->request('eve', 'anything'));
    }

    public function testKnownUserWithWrongPasswordAlsoInvokesPasswordVerifyExactlyOnce(): void
    {
        // Symmetry check: an unknown username must cost exactly as many
        // password_verify() calls as a known one with a wrong password —
        // one, not zero vs one.
        $verify = $this->getFunctionMock(self::SUBJECT_NAMESPACE, 'password_verify');
        $verify->expects(self::once())->willReturn(false);

        $authenticator = new BasicAuthenticator(['ada' => password_hash('s3cret', PASSWORD_BCRYPT)]);

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($this->request('ada', 'wrong'));
    }

    public function testKnownTokenBasedUserAlsoInvokesPasswordVerifyExactlyOnce(): void
    {
        // The second, narrower timing oracle this fix closes: a token-
        // configured known user used to resolve entirely through the fast
        // hash_equals() branch, skipping password_verify() — distinguishing
        // "this username is token-based" from "unknown, or hash-based" by
        // timing alone. matches() must now pay the password_verify() cost
        // here too (against the dummy hash, result discarded), even though
        // the actual credential is an opaque token, not a hash.
        $verify = $this->getFunctionMock(self::SUBJECT_NAMESPACE, 'password_verify');
        $verify->expects(self::once())->willReturn(false);

        $authenticator = new BasicAuthenticator(['svc' => 'opaque-shared-token']);

        $authenticator->authenticate($this->request('svc', 'opaque-shared-token'));
    }

    private function request(string $user, #[\SensitiveParameter] string $password): FakeServerRequest
    {
        return new FakeServerRequest(headers: [
            Constant::AUTHORIZATION_HEADER => Constant::BASIC_PREFIX . base64_encode($user . ':' . $password),
        ]);
    }
}
