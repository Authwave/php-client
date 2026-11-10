<?php
namespace Authwave\Test;

use Authwave\Authenticator;
use Authwave\GlobalSessionContainer;
use Authwave\RedirectHandler;
use Authwave\SessionData;
use Authwave\Token;
use Authwave\TokenReuseException;
use Authwave\ProviderUri\LoginUri;
use Authwave\ProviderUri\LogoutUri;
use GT\Cipher\EncryptionFailureException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class TokenNonceTest extends TestCase {
	/** @return array<string, array{string, string}> */
	public static function changedRequests():array {
		return [
			"changed action" => ["action=login", "action=logout"],
			"changed return query" => ["action=login&returnQuery=page%3D1", "action=login&returnQuery=page%3D2"],
			"empty first message" => ["", "action=login"],
			"empty second message" => ["action=login", ""],
		];
	}

	#[DataProvider("changedRequests")]
	public function testDifferentRequestsCannotShareToken(string $first, string $second):void {
		$token = new Token(str_repeat("s", 32));
		$iv = $token->getIv()->getBytes();
		$cipher = (string)$token->generateRequestCipher($first);
		try {
			$token->generateRequestCipher($second);
			self::fail("Expected token reuse to be rejected");
		}
		catch(TokenReuseException) {}
		self::assertSame($iv, $token->getIv()->getBytes());
		self::assertSame($cipher, (string)$token->generateRequestCipher($first));
	}

	public function testSessionSerialisationPreservesTheRequestBinding():void {
		$token = new Token(str_repeat("s", 32));
		$cipher = (string)$token->generateRequestCipher("action=login");
		/** @var SessionData $restored */
		$restored = unserialize(serialize(new SessionData($token)));
		self::assertSame($cipher, (string)$restored->getToken()->generateRequestCipher("action=login"));
		self::expectException(TokenReuseException::class);
		$restored->getToken()->generateRequestCipher("action=logout");
	}

	public function testUnusedTokenCanBeRestoredBeforeFirstEncryption():void {
		/** @var Token $token */
		$token = unserialize(serialize(new Token(str_repeat("s", 32))));
		self::assertNotSame("", (string)$token->generateRequestCipher("action=login"));
	}

	public function testLegacySessionCanDecryptButCannotReuseUnknownRequestNonce():void {
		$secret = str_repeat("s", 32);
		$token = new Token($secret);
		$fields = "";
		foreach(["key", "secretSessionIv", "iv"] as $name) {
			$value = (new \ReflectionProperty(Token::class, $name))->getValue($token);
			$fields .= serialize("\0" . Token::class . "\0" . $name) . serialize($value);
		}
		/** @var Token $legacy */
		$legacy = unserialize('O:' . strlen(Token::class) . ':"' . Token::class . '":3:{' . $fields . '}');
		$cipher = sodium_crypto_secretbox(
			'{"id":"user-id","email":"person@example.com"}',
			$token->getIv()->getBytes(), $secret,
		);
		self::assertSame("user-id", $legacy->decode(base64_encode($cipher))->getId());
		self::expectException(TokenReuseException::class);
		$legacy->generateRequestCipher("action=login");
	}

	public function testFailedEncryptionDoesNotBindTheToken():void {
		$token = new Token("");
		$failures = 0;
		foreach(["action=login", "action=logout"] as $message) {
			try {
				$token->generateRequestCipher($message);
				self::fail("Expected invalid key to fail encryption");
			}
			catch(EncryptionFailureException) { $failures++; }
		}
		self::assertSame(2, $failures);
	}

	public function testLoginAndLogoutBuildersRequireSeparateTokens():void {
		$token = new Token(str_repeat("s", 32));
		$uri = new LoginUri($token, "/callback", "deployment");
		self::assertSame((string)$uri, (string)new LoginUri($token, "/callback", "deployment"));
		self::expectException(TokenReuseException::class);
		new LogoutUri($token, "/callback", "deployment");
	}

	public function testRejectedLoginLeavesExistingExchangeUntouched():void {
		$secret = str_repeat("s", 32);
		$pending = new SessionData(new Token($secret));
		$_SESSION = [SessionData::class => $pending, "basket" => ["tea"]];
		$auth = new Authenticator(
			"deployment_" . $secret, "/callback",
			session: new GlobalSessionContainer(),
			redirectHandler: self::createStub(RedirectHandler::class),
		);
		$used = new Token($secret);
		$used->generateRequestCipher("action=logout");
		try {
			$auth->login($used);
			self::fail("Expected token reuse to be rejected");
		}
		catch(TokenReuseException) {}
		self::assertSame($pending, $_SESSION[SessionData::class]);
		self::assertSame(["tea"], $_SESSION["basket"]);
	}
}
