<?php
namespace Authwave\Test;

use Authwave\Authenticator;
use Authwave\AuthUser;
use Authwave\NotLoggedInException;
use Authwave\ProviderUri\BaseProviderUri;
use Authwave\ProviderUri\LoginUri;
use Authwave\RedirectHandler;
use Authwave\ResponseData\BaseResponseData;
use Authwave\SessionData;
use Authwave\SessionNotStartedException;
use Authwave\Token;
use Authwave\ResponseData\UserResponseData;
use Gt\Cipher\CipherText;
use Gt\Cipher\InitVector;
use Gt\Http\Uri;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\WithoutErrorHandler;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;

#[AllowMockObjectsWithoutExpectations]
class AuthenticatorTest extends TestCase {
	public function testResponseCipherPreservesRawPlusCharacters():void {
		$reflection = new \ReflectionClass(Authenticator::class);
		/** @var Authenticator $sut */
		$sut = $reflection->newInstanceWithoutConstructor();
		$currentUri = $reflection->getProperty("currentUriPath");
		$currentUri->setValue(
			$sut,
			new Uri("/?AUTHWAVE_RESPONSE_DATA=abc+def%3D%3D"),
		);
		$getQueryData = $reflection->getMethod("getQueryData");

		self::assertSame("abc+def==", $getQueryData->invoke($sut));
	}

	public function testConstructWithDefaultSessionNotStarted() {
		self::expectException(SessionNotStartedException::class);
		new Authenticator(
			"test-key",
			"/"
		);
	}

	public function testIsLoggedInFalseByDefault() {
		$_SESSION = [];
		$sut = new Authenticator(
			"test-key",
			"/"
		);
		self::assertFalse($sut->isLoggedIn());
	}

	public function testIsLoggedInTrueWhenSessionDataSet() {
		$userData = self::createMock(UserResponseData::class);
		$sessionData = self::createMock(SessionData::class);
		$sessionData->expects(self::once())
			->method("getData")
			->willReturn($userData);

		/** @noinspection PhpArrayWriteIsNotUsedInspection */
		$_SESSION = [
			SessionData::class => $sessionData
		];

		$sut = new Authenticator(
			"test-key",
			"/"
		);
		self::assertTrue($sut->isLoggedIn());
	}

	public function testSessionWithoutResponseDataIsNotLoggedIn():void {
		$_SESSION = [SessionData::class => new SessionData(new Token(str_repeat("s", 32)))];

		$sut = new Authenticator("deployment_" . str_repeat("s", 32), "/");

		self::assertFalse($sut->isLoggedIn());
	}

	public function testLoginCreatesAndStoresDefaultToken():void {
		$_SESSION = [];
		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::once())->method("redirect");
		$sut = new Authenticator(
			"deployment_" . str_repeat("s", 32),
			"/",
			redirectHandler: $redirectHandler,
		);

		$sut->login();

		self::assertInstanceOf(SessionData::class, $_SESSION[SessionData::class]);
		self::assertInstanceOf(Token::class, $_SESSION[SessionData::class]->getToken());
	}

	public function testLoginRedirectsWithCorrectQueryString() {
		$_SESSION = [];

		$deploymentId = uniqid("deployment-");
		$key = $deploymentId . "_secret";
		$currentPath = uniqid("/path/") . "?signup=free";

		$cipherString = "example-cipher";
		$cipher = self::createMock(CipherText::class);
		$cipher->method("__toString")->willReturn($cipherString);
		$ivString = "example-iv";

		$iv = self::createMock(InitVector::class);
		$iv->method("__toString")
			->willReturn($ivString);

		$token = self::createMock(Token::class);
		$token->method("generateRequestCipher")
			->willReturn($cipher);
		$token->method("getIv")
			->willReturn($iv);

		$expectedQueryParts = [
			LoginUri::QUERY_STRING_CIPHER => (string)$cipher,
			LoginUri::QUERY_STRING_DEPLOYMENT_ID => $deploymentId,
			LoginUri::QUERY_STRING_INIT_VECTOR => $ivString,
			LoginUri::QUERY_STRING_CURRENT_URI => bin2hex($currentPath),
		];
		$expectedQuery = http_build_query($expectedQueryParts);

		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::once())
			->method("redirect")
			->with(self::callback(fn(UriInterface $uri) =>
				$uri->getQuery() === $expectedQuery
			));

		$sut = new Authenticator(
			$key,
			$currentPath,
			LoginUri::DEFAULT_BASE_REMOTE_URI,
			null,
			$redirectHandler
		);
		$sut->login($token);
		self::assertSame("signup=free", $_SESSION[SessionData::class]->getReturnQuery());
	}

	public function testGetUuid() {
		$exampleId = uniqid("example-id-");

		$userData = self::createMock(UserResponseData::class);
		$userData->method("getId")
			->willReturn($exampleId);
		$sessionData = self::createMock(SessionData::class);
		$sessionData->method("getData")
			->willReturn($userData);

		$_SESSION = [
			SessionData::class => $sessionData,
		];
		$sut = new Authenticator(
			"test-key",
			"/"
		);
		self::assertEquals($exampleId, $sut->getAuthUser()->id);
	}

	public function testGetEmailThrowsExceptionWhenNotLoggedIn() {
		$_SESSION = [];
		$sut = new Authenticator(
			"test-key",
			"/"
		);
		self::expectException(NotLoggedInException::class);
		$sut->getAuthUser()->email;
	}

	public function testGetEmail() {
		$expectedEmail = "example@example.com";

		$userData = self::createMock(UserResponseData::class);
		$userData->method("getEmail")
			->willReturn($expectedEmail);
		$sessionData = self::createMock(SessionData::class);
		$sessionData->method("getData")
			->willReturn($userData);

		$_SESSION = [
			SessionData::class => $sessionData,
		];
		$sut = new Authenticator(
			"test-key",
			"/"
		);
		self::assertEquals($expectedEmail, $sut->getAuthUser()->email);
	}

	#[WithoutErrorHandler]
	public function testGetUserEmitsDeprecationAndReturnsCompatibilityUser():void {
		$_SESSION = [
			SessionData::class => new SessionData(
				new Token(str_repeat("s", 32)),
				new UserResponseData("user-id", "person@example.com"),
			),
		];
		$sut = new Authenticator("deployment_" . str_repeat("s", 32), "/");
		$deprecation = null;
		set_error_handler(function(int $level, string $message) use (&$deprecation):bool {
			$deprecation = [$level, $message];
			return true;
		});

		try {
			$user = $sut->getUser();
		}
		finally {
			restore_error_handler();
		}

		self::assertSame([
			E_USER_DEPRECATED,
			"Authenticator::getUser() is deprecated; use getAuthUser() instead.",
		], $deprecation);
		self::assertInstanceOf(AuthUser::class, $user);
		self::assertSame($user, $sut->getAuthUser());
	}

	#[WithoutErrorHandler]
	public function testDeprecatedGetUserStillThrowsWhenNotLoggedIn():void {
		$_SESSION = [];
		$sut = new Authenticator("deployment_" . str_repeat("s", 32), "/");
		set_error_handler(static fn():bool => true);

		try {
			self::expectException(NotLoggedInException::class);
			$sut->getUser();
		}
		finally {
			restore_error_handler();
		}
	}

	public function testCompleteAuthNotAffectedByQueryString() {
		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::never())
			->method("redirect");
		$_SESSION = [];

		new Authenticator(
			"test-key",
			"/example-path/?filter=something",
			LoginUri::DEFAULT_BASE_REMOTE_URI,
			null,
			$redirectHandler
		);
	}

	public function testAcceptsPsrUriInterfaceForCurrentUriPath():void {
		$_SESSION = [];
		$currentUriPath = self::createStub(UriInterface::class);
		$currentUriPath->method("__toString")->willReturn("/psr-path");
		$currentUriPath->method("getQuery")->willReturn("");
		$sut = new Authenticator("deployment_secret", $currentUriPath);
		$token = self::createStub(Token::class);
		$token->method("generateRequestCipher")->willReturn(self::createStub(CipherText::class));
		$token->method("getIv")->willReturn(self::createStub(InitVector::class));

		parse_str($sut->getLoginUri($token)->getQuery(), $query);

		self::assertSame(
			bin2hex("/psr-path"),
			$query[BaseProviderUri::QUERY_STRING_CURRENT_URI],
		);
	}

	public function testSetReturnUriOverridesLoginReturnLocation():void {
		$_SESSION = [];
		$sut = new Authenticator("deployment_secret", "/current-path");
		$sut->setReturnUri("/after-login?source=authwave");
		$token = self::createStub(Token::class);
		$token->method("generateRequestCipher")->willReturn(self::createStub(CipherText::class));
		$token->method("getIv")->willReturn(self::createStub(InitVector::class));

		parse_str($sut->getLoginUri($token)->getQuery(), $query);

		self::assertSame(
			bin2hex("/after-login?source=authwave"),
			$query[BaseProviderUri::QUERY_STRING_CURRENT_URI],
		);
	}

	public function testGetAdminUri() {
		$_SESSION = [];
		$auth = new Authenticator(
			"test-key",
			"/example-path",
			BaseProviderUri::DEFAULT_BASE_REMOTE_URI
		);
		$sut = $auth->getAdminUri();
		self::assertEquals(
			"/admin/",
			$sut->getPath()
		);
	}

	public function testCompleteAuthNotLoggedIn() {
		$currentUri = "/?"
			. Authenticator::RESPONSE_QUERY_PARAMETER
			. "=0123456789abcdef";

		$_SESSION = [];
		$redirectHandler = self::createStub(RedirectHandler::class);
		self::expectException(NotLoggedInException::class);
		$sut = new Authenticator(
			"test-key",
			$currentUri,
			LoginUri::DEFAULT_BASE_REMOTE_URI,
			null,
			$redirectHandler,
		);
		$sut->getAuthUser();
	}

// When the remote provider redirects back to the client application, a query
// string parameter is provided containing encrypted user and config data.
// In this example, we make our own query string parameter, which will NOT
// decrypt properly, and should throw an exception to prevent unauthorised
// access.
	public function testCompleteAuth() {
		$keyBytes = str_repeat("0", SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
		$ivBytes = str_repeat("1", SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
		$plainTextMessage = json_encode([
			"id" => 123,
			"email" => "person@example.com",
		]);
		$encryptedMessage = sodium_crypto_secretbox(
			$plainTextMessage,
			$ivBytes,
			$keyBytes,
		);

		$currentUri = "/my-page?filter=example&"
			. Authenticator::RESPONSE_QUERY_PARAMETER
			. "="
			. urlencode(base64_encode($encryptedMessage));

		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::once())
			->method("redirect")
			->with(self::callback(fn(UriInterface $uri) =>
				$uri->getQuery() === "filter=original"
				&& $uri->getPath() === "/my-page"
			));
		$iv = self::createMock(InitVector::class);
		$iv->method("getBytes")->willReturn($ivBytes);
		$token = self::createMock(Token::class);
		$token->method("getSecretIv")
			->willReturn($iv);

		$sessionData = self::createMock(SessionData::class);
		$sessionData->method("getToken")
			->willReturn($token);
		$sessionData->method("getReturnQuery")->willReturn("filter=original");

		$_SESSION = [
			SessionData::class => $sessionData,
		];
		$authenticatedUser = null;

		new Authenticator(
			"deployment_$keyBytes",
			$currentUri,
			LoginUri::DEFAULT_BASE_REMOTE_URI,
			null,
			$redirectHandler,
			onAuthenticated: function(AuthUser $user) use (&$authenticatedUser):void {
				$authenticatedUser = $user;
			},
		);

		/** @var SessionData $newSessionData */
		$newSessionData = $_SESSION[SessionData::class];
		self::assertNotSame($sessionData, $newSessionData);
		self::assertInstanceOf(
			SessionData::class,
			$newSessionData
		);
		self::assertInstanceOf(
			BaseResponseData::class,
			$newSessionData->getData()
		);
		self::assertTrue($newSessionData->hasInvokedAuthenticationCallback());
		self::assertInstanceOf(AuthUser::class, $authenticatedUser);
		self::assertSame("person@example.com", $authenticatedUser->email);
	}

	public function testAuthenticationCallbackIsAtMostOnceWhenItThrows():void {
		$keyBytes = str_repeat("0", SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
		$ivBytes = str_repeat("1", SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
		$encryptedMessage = sodium_crypto_secretbox(
			json_encode([
				"id" => "user-id",
				"email" => "person@example.com",
			]),
			$ivBytes,
			$keyBytes,
		);
		$currentUri = "/?" . Authenticator::RESPONSE_QUERY_PARAMETER
			. "=" . urlencode(base64_encode($encryptedMessage));
		$iv = self::createStub(InitVector::class);
		$iv->method("getBytes")->willReturn($ivBytes);
		$token = self::createStub(Token::class);
		$token->method("getSecretIv")->willReturn($iv);
		$_SESSION = [SessionData::class => new SessionData($token, returnQuery: "tab=orders")];
		$callbackCount = 0;
		$callback = function(AuthUser $user) use (&$callbackCount):void {
			$callbackCount++;
			throw new \RuntimeException("Application callback failed");
		};

		try {
			new Authenticator(
				"deployment_$keyBytes",
				$currentUri,
				redirectHandler: self::createStub(RedirectHandler::class),
				onAuthenticated: $callback,
			);
			self::fail("Expected the application callback to throw");
		}
		catch(\RuntimeException $exception) {
			self::assertSame("Application callback failed", $exception->getMessage());
		}

		self::assertTrue($_SESSION[SessionData::class]->hasInvokedAuthenticationCallback());
		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::once())->method("redirect")
			->with(self::callback(fn(UriInterface $uri) => $uri->getQuery() === "tab=orders"));
		new Authenticator(
			"deployment_$keyBytes",
			$currentUri,
			redirectHandler: $redirectHandler,
			onAuthenticated: $callback,
		);

		self::assertSame(1, $callbackCount);
		self::assertSame("tab=orders", $_SESSION[SessionData::class]->getReturnQuery());
	}

	public function testLoginDoesNothingWhenAlreadyLoggedIn() {
		$sessionData = self::createMock(SessionData::class);
		$sessionData->method("getData")
			->willReturn(self::createMock(UserResponseData::class));
		$_SESSION = [
			SessionData::class => $sessionData,
		];

		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::never())
			->method("redirect");

		$sut = new Authenticator(
			"test-key",
			"/",
			LoginUri::DEFAULT_BASE_REMOTE_URI,
			null,
			$redirectHandler
		);

		$token = self::createMock(Token::class);
		$requestCipherString = "example-request-cipher";
		$requestCipher = self::createMock(CipherText::class);
		$requestCipher->method("__toString")->willReturn($requestCipherString);
		$ivBytes = "0123456789";
		$iv = self::createMock(InitVector::class);
		$iv->method("__toString")->willReturn($ivBytes);

		$token->method("generateRequestCipher")
			->willReturn($requestCipher);
		$token->method("getIv")
			->willReturn($iv);
		$sut->login($token);
	}

	public function testGetUuidThrowsExceptionWhenNotLoggedIn() {
		$_SESSION = [];
		$sut = new Authenticator(
			"test-key",
			"/"
		);
		self::expectException(NotLoggedInException::class);
		$sut->getAuthUser()->id;
	}

	public function testLogoutCallsLogoutUri() {
		$sessionData = self::createMock(SessionData::class);
		$_SESSION = [
			SessionData::class => $sessionData
		];

		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::once())
			->method("redirect")
			->with(self::callback(function(UriInterface $uri):bool {
				if($uri->getHost() !== "login.authwave.com") {
					return false;
				}

				parse_str($uri->getQuery(), $queryParts);
				if($queryParts[BaseProviderUri::QUERY_STRING_CURRENT_URI]
				!== bin2hex("/after-logout")) {
					return false;
				}
				return !isset($_SESSION[SessionData::class]);
			}));

		$sut = new Authenticator(
			"test-key",
			"/",
			LoginUri::DEFAULT_BASE_REMOTE_URI,
			null,
			$redirectHandler
		);
		$sut->setReturnUri("/after-logout");
		$token = self::createMock(Token::class);
		$cipherString = "example-request-cipher";
		$cipher = self::createMock(CipherText::class);
		$cipher->method("__toString")->willReturn($cipherString);
		$token->method("generateRequestCipher")
			->willReturn($cipher);
		$ivBytes = "01234567890";
		$iv = self::createMock(InitVector::class);
		$iv->method("__toString")->willReturn($ivBytes);
		$token->method("getIv")
			->willReturn($iv);
		$sut->logout(token: $token);
		self::assertArrayNotHasKey(SessionData::class, $_SESSION);
	}

	public function testLogoutCreatesDefaultToken():void {
		$_SESSION = [];
		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::once())->method("redirect");
		$sut = new Authenticator(
			"deployment_" . str_repeat("s", 32),
			"/",
			redirectHandler: $redirectHandler,
		);

		$sut->logout();

		self::assertArrayNotHasKey(SessionData::class, $_SESSION);
	}

	public function testLogoutFakeUserClearsSessionWithoutRedirect():void {
		$token = new Token(str_repeat("s", 32));
		$_SESSION = [
			SessionData::class => new SessionData(
				$token,
				new UserResponseData("user-id", Authenticator::FAKE_EMAIL),
			),
		];
		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::never())->method("redirect");
		$sut = new Authenticator(
			"deployment_" . str_repeat("s", 32),
			"/",
			redirectHandler: $redirectHandler,
		);

		$sut->logout();

		self::assertFalse($sut->isLoggedIn());
		self::assertArrayNotHasKey(SessionData::class, $_SESSION);
	}

	public function testFakeLoginStoresUserAndRemovesCurrentQuery():void {
		$_SESSION = [];
		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::once())
			->method("redirect")
			->with(self::callback(function(UriInterface $uri):bool {
				parse_str($uri->getQuery(), $query);
				return $uri->getPath() === "/destination"
					&& !isset($query["filter"])
					&& isset($query[Authenticator::RESPONSE_QUERY_PARAMETER]);
			}));
		$sut = new Authenticator(
			"deployment_" . str_repeat("s", 32),
			"/current?filter=active",
			redirectHandler: $redirectHandler,
		);

		$sut->fakeLogin("user-id", redirectTo: "/destination");

		$userData = $_SESSION[SessionData::class]->getData();
		self::assertSame("user-id", $userData->getId());
		self::assertSame(Authenticator::FAKE_EMAIL, $userData->getEmail());
	}

	public function testGetProfileUriWithGeneratedAndProvidedTokens():void {
		$_SESSION = [
			SessionData::class => new SessionData(
				new Token(str_repeat("s", 32)),
				new UserResponseData("user-id", "person@example.com"),
			),
		];
		$sut = new Authenticator("deployment_" . str_repeat("s", 32), "/account");
		$sut->setReturnUri("/after-profile");

		$generatedTokenUri = $sut->getProfileUri();
		$providedTokenUri = $sut->getProfileUri(new Token(str_repeat("s", 32)));

		self::assertSame("/profile/", $generatedTokenUri->getPath());
		parse_str($generatedTokenUri->getQuery(), $query);
		self::assertSame("user-id", $query[BaseProviderUri::QUERY_STRING_DEPLOYMENT_ID]);
		self::assertSame(bin2hex("/after-profile"), $query[BaseProviderUri::QUERY_STRING_CURRENT_URI]);
		self::assertSame("/profile/", $providedTokenUri->getPath());
	}

	#[\PHPUnit\Framework\Attributes\DataProvider("provideLogoutRedirect")]
	public function testLogoutUsesRequestedRedirect(
		string|UriInterface $redirectTo,
		string $expectedRedirect,
	):void {
		$_SESSION = [];
		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::once())
			->method("redirect")
			->with(self::isInstanceOf(UriInterface::class));

		$sut = new Authenticator(
			"test-key",
			"https://example.com/current/path?old=value",
			LoginUri::DEFAULT_BASE_REMOTE_URI,
			null,
			$redirectHandler,
		);

		$token = self::createMock(Token::class);
		$cipher = self::createMock(CipherText::class);
		$cipher->method("__toString")->willReturn("example-request-cipher");
		$token->expects(self::once())
			->method("generateRequestCipher")
			->with(http_build_query([
				"action" => "logout",
				"redirectTo" => $expectedRedirect,
			]))
			->willReturn($cipher);
		$iv = self::createMock(InitVector::class);
		$iv->method("__toString")->willReturn("01234567890");
		$token->method("getIv")->willReturn($iv);

		$sut->logout($redirectTo, $token);
	}

	public static function provideLogoutRedirect():array {
		return [
			"path string" => [
				"/you-have-been-logged-out",
				"/you-have-been-logged-out",
			],
			"query string" => [
				"?whatever=something",
				"https://example.com/current/path?whatever=something",
			],
			"URI object" => [
				new Uri("https://example.com/signed-out"),
				"https://example.com/signed-out",
			],
		];
	}

	public function testLoginRedirects() {
		$_SESSION = [];

		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::once())
			->method("redirect")
			->with(self::callback(fn(UriInterface $uri) =>
				$uri->getHost() === LoginUri::DEFAULT_BASE_REMOTE_URI
			));

		$sut = new Authenticator(
			"test-key",
			"/",
			LoginUri::DEFAULT_BASE_REMOTE_URI,
			null,
			$redirectHandler
		);

		$token = self::createMock(Token::class);
		$cipherString = "example-request-cipher";
		$cipher = self::createMock(CipherText::class);
		$cipher->method("__toString")->willReturn($cipherString);
		$token->method("generateRequestCipher")
			->willReturn($cipher);
		$ivBytes = "01234567890";
		$iv = self::createMock(InitVector::class);
		$iv->method("__toString")->willReturn($ivBytes);
		$token->method("getIv")
			->willReturn($iv);
		$sut->login($token);
	}

	public function testLoginRedirectsLocalhost() {
		$_SESSION = [];

		$redirectHandler = self::createMock(RedirectHandler::class);
		$redirectHandler->expects(self::once())
			->method("redirect")
			->with(self::callback(fn(UriInterface $uri) =>
				$uri->getScheme() === "http"
				&& $uri->getHost() === "localhost"
				&& $uri->getPort() === 8081
			));

		$sut = new Authenticator(
			"test-key",
			"/",
			"http://localhost:8081",
			null,
			$redirectHandler
		);
		$token = self::createMock(Token::class);
		$cipherString = "example-request-cipher";
		$cipher = self::createMock(CipherText::class);
		$cipher->method("__toString")->willReturn($cipherString);
		$token->method("generateRequestCipher")
			->willReturn($cipher);
		$ivBytes = "01234567890";
		$iv = self::createMock(InitVector::class);
		$iv->method("__toString")->willReturn($ivBytes);
		$token->method("getIv")
			->willReturn($iv);
		$sut->login($token);
	}
}
