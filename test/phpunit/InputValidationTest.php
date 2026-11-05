<?php
namespace Authwave\Test;

use Authwave\Authenticator;
use Authwave\InvalidClientKeyException;
use Authwave\InvalidUserDataSerializationException;
use Authwave\RedirectHandler;
use Authwave\ResponseCipherDecryptionException;
use Authwave\SessionData;
use Authwave\Token;
use GT\Cipher\InitVector;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class InputValidationTest extends TestCase {
	public static function invalidKeys():array {
		return [[""], ["missing-separator"], ["_" . str_repeat("s", 32)],
			["deployment_"], ["deployment_short"], ["deployment_" . str_repeat("s", 33)]];
	}

	#[DataProvider("invalidKeys")]
	public function testInvalidConfigurationFailsBeforeSessionAccess(string $key):void {
		unset($_SESSION);
		self::expectException(InvalidClientKeyException::class);
		new Authenticator($key, "/");
	}

	public static function invalidQueries():array {
		return [[""], ["[]=cipher"], ["[nested]=cipher"], ["=%%%"], ["=0"]];
	}

	#[DataProvider("invalidQueries")]
	public function testInvalidCallbackParameterLeavesSessionUntouched(string $suffix):void {
		$_SESSION = ["basket" => ["tea"]];
		$before = $_SESSION;
		$redirect = self::createMock(RedirectHandler::class);
		$redirect->expects(self::never())->method("redirect");
		try {
			new Authenticator("deployment_" . str_repeat("s", 32),
				"/?AUTHWAVE_RESPONSE_DATA" . $suffix, redirectHandler: $redirect);
			self::fail("Expected invalid callback input to fail");
		}
		catch(ResponseCipherDecryptionException) {}
		self::assertSame($before, $_SESSION);
	}

	public static function invalidPayloads():array {
		return [["not json"], ["null"], ["[]"], ["{}"],
			['{"id":123,"email":"person@example.com"}'],
			['{"id":"user","email":false}'],
			['{"id":[],"email":"person@example.com"}'],
			['{"id":"user"}'], ['{"email":"person@example.com"}']];
	}

	#[DataProvider("invalidPayloads")]
	public function testBothResponsePathsRejectInvalidPayloads(string $json):void {
		$key = str_repeat("s", 32);
		$iv = new InitVector();
		$token = new Token($key, $iv, $iv);
		$cipher = base64_encode(sodium_crypto_secretbox($json, $iv->getBytes(), $key));
		$pending = new SessionData($token, returnQuery: "tab=orders");
		$_SESSION = [SessionData::class => $pending, "basket" => ["tea"]];
		$before = $_SESSION;
		$redirect = self::createMock(RedirectHandler::class);
		$redirect->expects(self::never())->method("redirect");
		$callback = static function():void { self::fail("Invalid response invoked callback"); };
		try {
			new Authenticator("deployment_" . $key,
				"/?AUTHWAVE_RESPONSE_DATA=" . urlencode($cipher),
				redirectHandler: $redirect, onAuthenticated: $callback);
			self::fail("Expected callback validation to fail");
		}
		catch(InvalidUserDataSerializationException) {}
		self::assertSame($before, $_SESSION);
		self::assertFalse($pending->hasInvokedAuthenticationCallback());
		self::expectException(InvalidUserDataSerializationException::class);
		$token->decode($cipher);
	}

	public function testUuidResponsesWorkInBothPaths():void {
		$key = str_repeat("s", 32);
		$iv = new InitVector();
		$token = new Token($key, $iv, $iv);
		$cipher = base64_encode(sodium_crypto_secretbox(
			'{"uuid":"user-id","email":"person@example.com"}', $iv->getBytes(), $key,
		));
		$_SESSION = [SessionData::class => new SessionData($token)];
		$auth = new Authenticator("deployment_" . $key,
			"/?AUTHWAVE_RESPONSE_DATA=" . urlencode($cipher),
			redirectHandler: self::createStub(RedirectHandler::class));
		self::assertSame("user-id", $auth->getAuthUser()->id);
		self::assertSame("user-id", $token->decode($cipher)->getId());
	}

	public function testTokenRejectsMalformedCipherEncoding():void {
		self::expectException(ResponseCipherDecryptionException::class);
		(new Token(str_repeat("s", 32)))->decode("%%%");
	}

	public function testDeploymentIdCanContainUnderscores():void {
		$_SESSION = [];
		$auth = new Authenticator("my_deployment_" . str_repeat("s", 32), "/");
		self::assertFalse($auth->isLoggedIn());
	}
}
