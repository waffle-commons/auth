<?php

declare(strict_types=1);

namespace Waffle\Commons\Auth\Credential;

use Psr\Http\Message\RequestInterface;
use Waffle\Commons\Auth\Uab\UserAssertion;
use Waffle\Commons\Contracts\Auth\Assertion\AssertionSignerInterface;
use Waffle\Commons\Contracts\Auth\Constant;
use Waffle\Commons\Contracts\Auth\CredentialsProviderInterface;
use Waffle\Commons\Contracts\Auth\SecurityContextInterface;

/**
 * Outbound Gateway Assertion scheme (RFC-021 §4.3 sender side): when the
 * request targets an allow-listed host AND the SecurityContext holds an
 * authenticated identity with a recorded client IP, a freshly signed
 * `X-Wfl-Assert-User` header is attached (`iat = now`, `exp = iat + 5`).
 *
 * Anonymous context ⇒ no header (anonymous proxying). Existing header ⇒
 * left untouched. Unlisted host ⇒ not supported (credentials never leak).
 */
final readonly class AssertionCredentialsProvider implements CredentialsProviderInterface
{
    /** @var list<string> Host allow-list, normalized to lowercase. */
    private array $allowedHosts;

    /**
     * @param list<string> $allowedHosts Host allow-list (matched case-insensitively).
     * @param string|null  $tenant       Tenant/organisation id stamped into
     *                                   every assertion (`ten`), when used.
     */
    public function __construct(
        private AssertionSignerInterface $signer,
        private SecurityContextInterface $context,
        array $allowedHosts,
        private ?string $tenant = null,
    ) {
        $this->allowedHosts = array_values(array_map(strtolower(...), $allowedHosts));
    }

    #[\Override]
    public function supports(RequestInterface $request): bool
    {
        return in_array(strtolower($request->getUri()->getHost()), $this->allowedHosts, true);
    }

    /**
     * @throws \InvalidArgumentException A claim-schema violation while
     *         building the assertion, or PSR-7 rejecting the internally
     *         built header — wiring faults, never request data.
     */
    #[\Override]
    public function apply(RequestInterface $request): RequestInterface
    {
        if ($request->hasHeader(Constant::ASSERTION_HEADER)) {
            return $request;
        }

        $identity = $this->context->getIdentity();
        $clientIp = $this->context->getClientIp();
        if ($identity === null || $clientIp === null || $clientIp === '') {
            return $request;
        }

        $now = time();
        $assertion = new UserAssertion(
            subject: $identity->subject,
            email: $identity->email,
            roles: $identity->roles,
            tenant: $this->tenant,
            issuedAt: $now,
            expiresAt: $now + Constant::ASSERTION_TTL,
            ipHash: $this->signer->hashClientIp($clientIp),
        );

        return $request->withHeader(Constant::ASSERTION_HEADER, $this->signer->sign($assertion));
    }
}
