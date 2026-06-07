<?php

declare(strict_types=1);

namespace WaffleTests\Commons\Auth\Middleware;

use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Log\AbstractLogger;
use Waffle\Commons\Auth\AuthenticationBridge;
use Waffle\Commons\Auth\Authenticator\ApiKeyAuthenticator;
use Waffle\Commons\Auth\Exception\AuthenticationException;
use Waffle\Commons\Auth\Identity\UserIdentity;
use Waffle\Commons\Auth\Middleware\AuthenticationMiddleware;
use Waffle\Commons\Auth\SecurityContext;
use Waffle\Commons\Contracts\Auth\Constant;
use WaffleTests\Commons\Auth\AbstractTestCase;
use WaffleTests\Commons\Auth\Helper\FakeServerRequest;
use WaffleTests\Commons\Auth\Helper\PassHandler;

#[CoversClass(AuthenticationMiddleware::class)]
final class AuthenticationMiddlewareTest extends AbstractTestCase
{
    public function testAnonymousRequestsPassThroughUnchanged(): void
    {
        $middleware = new AuthenticationMiddleware($this->bridge());
        $handler = new PassHandler();
        $request = new FakeServerRequest();

        $middleware->process($request, $handler);

        self::assertNotNull($handler->received);
        self::assertNull(self::received($handler)->getAttribute(Constant::REQUEST_ATTRIBUTE));
    }

    public function testAuthenticatedRequestsCarryTheIdentityAttribute(): void
    {
        $middleware = new AuthenticationMiddleware($this->bridge());
        $handler = new PassHandler();
        $request = new FakeServerRequest(headers: [Constant::API_KEY_HEADER => 'the-key']);

        $middleware->process($request, $handler);

        self::assertNotNull($handler->received);
        $identity = self::received($handler)->getAttribute(Constant::REQUEST_ATTRIBUTE);
        self::assertInstanceOf(UserIdentity::class, $identity);
        self::assertSame('svc-api', $identity->subject);
    }

    public function testRejectionsAreLoggedAndRethrown(): void
    {
        $logger = new class extends AbstractLogger {
            /** @var list<string> */
            public array $messages = [];

            #[\Override]
            public function log(mixed $level, \Stringable|string $message, array $context = []): void
            {
                $this->messages[] = (string) $message;
            }
        };

        $middleware = new AuthenticationMiddleware($this->bridge(), $logger);
        $request = new FakeServerRequest(headers: [Constant::API_KEY_HEADER => 'wrong-key']);

        try {
            $middleware->process($request, new PassHandler());
            self::fail('An AuthenticationException was expected.');
        } catch (AuthenticationException) {
            self::assertSame(['Authentication rejected.'], $logger->messages);
        }
    }

    private function bridge(): AuthenticationBridge
    {
        return new AuthenticationBridge(new SecurityContext(), [
            new ApiKeyAuthenticator(['the-key' => new UserIdentity(subject: 'svc-api')]),
        ]);
    }
}
