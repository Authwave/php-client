<?php
namespace Authwave\Test;

use Authwave\Authenticator;
use Authwave\NotLoggedInException;
use Authwave\RedirectHandler;
use Authwave\ResponseData\UserResponseData;
use Authwave\SessionData;
use Authwave\Token;
use GT\Cipher\Key;
use GT\Cipher\InitVector;
use GT\Cipher\Message\EncryptedMessage;
use GT\Session\SessionArrayWrapper;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;

class LogoutTest extends TestCase {
	public function testLogoutClearsUserBeforeRedirectingToProvider():void {
		$secret = str_repeat("s", 32);
		$data = [
			SessionData::class => new SessionData(
				new Token($secret),
				new UserResponseData("user-id", "person@example.com"),
			),
			"basket" => ["tea"],
		];
		$session = new SessionArrayWrapper($data);
		$redirect = self::createMock(RedirectHandler::class);
		$auth = new Authenticator(
			"deployment_" . $secret,
			"/logout",
			session: $session,
			redirectHandler: $redirect,
		);
		self::assertTrue($auth->isLoggedIn());
		$redirect->expects(self::once())->method("redirect")
			->willReturnCallback(function() use ($auth, &$data):void {
				self::assertFalse($auth->isLoggedIn());
				self::assertArrayNotHasKey(SessionData::class, $data);
			});

		$auth->logout("/signed-out");

		self::assertSame(["basket" => ["tea"]], $data);
		self::assertFalse((new Authenticator("deployment_" . $secret, "/signed-out", session: $session))->isLoggedIn());
		self::expectException(NotLoggedInException::class);
		$auth->getAuthUser();
	}

	public function testLogoutEncryptsConfiguredReturnUriForProvider():void {
		$secret = str_repeat("s", 32);
		$data = [];
		$redirect = self::createMock(RedirectHandler::class);
		$redirect->expects(self::once())->method("redirect")
			->willReturnCallback(function(UriInterface $uri) use ($secret):void {
				self::assertSame("login.authwave.com", $uri->getHost());
				parse_str($uri->getQuery(), $query);
				self::assertSame("deployment", $query["d"]);
				$iv = (new InitVector())->withBytes(base64_decode($query["i"]));
				$message = (new EncryptedMessage($query["c"], $iv))->decrypt(new Key($secret));
				parse_str((string)$message, $payload);
				self::assertSame("logout", $payload["action"]);
				self::assertSame("/signed-out?source=authwave", $payload["redirectTo"] ?? null);
			});
		$auth = new Authenticator(
			"deployment_" . $secret,
			"/logout",
			session: new SessionArrayWrapper($data),
			redirectHandler: $redirect,
		);
		$auth->setReturnUri("/signed-out?source=authwave");

		$auth->logout();
	}
}
