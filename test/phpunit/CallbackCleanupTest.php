<?php
namespace Authwave\Test;

use Authwave\Authenticator;
use Authwave\GlobalSessionContainer;
use Authwave\RedirectHandler;
use Authwave\SessionData;
use Authwave\Token;
use GT\Http\Uri;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;

class CallbackCleanupTest extends TestCase {
	/** @return array<string, array{string, string}> */
	public static function cleanupUris():array {
		return [
			"network path" => ["//evil.example/path", "/path"],
			"network root" => ["//evil.example", "/"],
			"absolute URI" => ["https://evil.example/path", "/path"],
			"credentials" => ["https://user:pass@evil.example/path", "/path"],
			"multiple leading slashes" => ["https://app.example//evil.example/path", "/evil.example/path"],
			"backslash" => ["/\\evil.example/path", "/%5Cevil.example/path"],
			"encoded slashes" => ["/%2F%2Fevil.example/path", "/%2F%2Fevil.example/path"],
			"encoded path" => ["/members/a%2Fb", "/members/a%2Fb"],
			"ordinary path" => ["/members/orders", "/members/orders"],
		];
	}

	#[DataProvider("cleanupUris")]
	public function testUnsolicitedResponseRedirectsOnlyToLocalPath(string $input, string $expected):void {
		$_SESSION = [];
		$redirect = new class extends RedirectHandler {
			public ?UriInterface $uri = null;
			public function redirect(UriInterface $uri, int $code = 303):void {
				$this->uri = $uri;
			}
		};
		$auth = new Authenticator(
			"deployment_" . str_repeat("s", 32),
			$input . "?keep=%7e&flag&AUTHWAVE_RESPONSE_DATA=anything#details",
			redirectHandler: $redirect,
		);

		self::assertFalse($auth->isLoggedIn());
		self::assertNotNull($redirect->uri);
		self::assertSame($expected . "?keep=%7e&flag#details", (string)$redirect->uri);
		self::assertSame("", $redirect->uri->getScheme());
		self::assertSame("", $redirect->uri->getAuthority());
		self::assertStringStartsWith("/", (string)$redirect->uri);
		self::assertFalse(str_starts_with((string)$redirect->uri, "//"));
	}

	public function testAuthenticatedCleanupPreservesSavedQueryAndEncodedPath():void {
		$secret = str_repeat("s", 32);
		$token = new Token($secret);
		$_SESSION = [SessionData::class => new SessionData($token, returnQuery: "filter=original&flag&encoded=%7e")];
		// A map-only session has no native browser session ID.
		$session = new class extends GlobalSessionContainer {
			public function regenerate():void {}
		};
		$cipher = sodium_crypto_secretbox(
			'{"id":"user-id","email":"person@example.com"}',
			$token->getSecretIv()->getBytes(), $secret,
		);
		$redirect = self::createMock(RedirectHandler::class);
		$redirect->expects(self::once())->method("redirect")->with(self::callback(
			fn(UriInterface $uri):bool => (string)$uri === "/members/a%2Fb?filter=original&flag&encoded=%7e#details"
		));

		$auth = new Authenticator(
			"deployment_" . $secret,
			new Uri("https://user:pass@evil.example//members/a%2Fb?AUTHWAVE_RESPONSE_DATA="
				. urlencode(base64_encode($cipher)) . "#details"),
			session: $session,
			redirectHandler: $redirect,
		);
		self::assertSame("user-id", $auth->getAuthUser()->id);
	}

	public function testDuplicateResponseParametersAreRemoved():void {
		$_SESSION = [];
		$redirect = self::createMock(RedirectHandler::class);
		$redirect->expects(self::once())->method("redirect")->with(self::callback(
			fn(UriInterface $uri):bool => (string)$uri === "/path?flag&next=https://evil.example"
		));
		new Authenticator(
			"deployment_" . str_repeat("s", 32),
			"//evil.example/path?AUTHWAVE_RESPONSE_DATA=one&flag&AUTHWAVE_RESPONSE_DATA=two&next=https://evil.example",
			redirectHandler: $redirect,
		);
	}
}
