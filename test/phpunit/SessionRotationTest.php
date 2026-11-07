<?php
namespace Authwave\Test;

use Authwave\Authenticator;
use Authwave\GlobalSessionContainer;
use Authwave\RedirectHandler;
use Authwave\SessionData;
use Authwave\SessionRegenerationException;
use Authwave\Token;
use GT\Session\SessionArrayWrapper;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;

#[RunTestsInSeparateProcesses]
#[PreserveGlobalState(false)]
class SessionRotationTest extends TestCase {
	private string $sessionDirectory;

	protected function setUp():void {
		$this->sessionDirectory = sys_get_temp_dir() . "/authwave-rotation-" . bin2hex(random_bytes(8));
		mkdir($this->sessionDirectory);
		session_id("known-anonymous-session");
		session_start([
			"save_path" => $this->sessionDirectory,
			"use_cookies" => false,
			"cache_limiter" => "",
		]);
	}

	protected function tearDown():void {
		if(session_status() === PHP_SESSION_ACTIVE) {
			session_destroy();
		}
		foreach(glob($this->sessionDirectory . "/*") as $file) {
			unlink($file);
		}
		rmdir($this->sessionDirectory);
	}

	private function responseUri(Token $token):string {
		$cipher = sodium_crypto_secretbox(
			'{"id":"user-id","email":"person@example.com"}',
			$token->getSecretIv()->getBytes(),
			str_repeat("s", 32),
		);
		return "/callback?AUTHWAVE_RESPONSE_DATA=" . urlencode(base64_encode($cipher));
	}

	private function redirect():RedirectHandler {
		return new class extends RedirectHandler {
			public function redirect(UriInterface $uri, int $code = 303):void {}
		};
	}

	public function testAuthenticationRotatesBeforeCallbackAndInvalidatesOldSession():void {
		$token = new Token(str_repeat("s", 32));
		$_SESSION[SessionData::class] = new SessionData($token);
		$_SESSION["basket"] = ["tea"];
		$oldId = session_id();
		$callbackId = null;
		$uri = $this->responseUri($token);

		new Authenticator(
			"deployment_" . str_repeat("s", 32),
			$uri,
			redirectHandler: $this->redirect(),
			onAuthenticated: function() use (&$callbackId):void {
				$callbackId = session_id();
			},
		);
		$newId = session_id();
		self::assertNotSame($oldId, $newId);
		self::assertSame($newId, $callbackId);
		self::assertSame(["tea"], $_SESSION["basket"]);
		self::assertSame("user-id", $_SESSION[SessionData::class]->getData()->getId());
		session_write_close();

		session_id($oldId);
		session_start();
		$oldSession = new Authenticator(
			"deployment_" . str_repeat("s", 32), $uri, redirectHandler: $this->redirect(),
		);
		self::assertFalse($oldSession->isLoggedIn());
		self::assertArrayNotHasKey(SessionData::class, $_SESSION);
		session_write_close();

		session_id($newId);
		session_start();
		$restored = new Authenticator("deployment_" . str_repeat("s", 32), "/");
		self::assertTrue($restored->isLoggedIn());
		self::assertSame($newId, session_id());
	}

	public function testInvalidCipherDoesNotRotate():void {
		$_SESSION[SessionData::class] = new SessionData(new Token(str_repeat("s", 32)));
		$id = session_id();
		try {
			new Authenticator(
				"deployment_" . str_repeat("s", 32), "/?AUTHWAVE_RESPONSE_DATA=invalid",
				redirectHandler: $this->redirect(),
			);
			self::fail("Expected decryption to fail");
		}
		catch(\GT\Cipher\Message\DecryptionFailureException) {}
		self::assertSame($id, session_id());
	}

	public function testFakeLoginRotatesBeforeStoringItsIdentity():void {
		$id = session_id();
		$_SESSION["basket"] = ["tea"];
		$auth = new Authenticator(
			"deployment_" . str_repeat("s", 32), "/", redirectHandler: $this->redirect(),
		);
		$auth->fakeLogin("developer");
		self::assertNotSame($id, session_id());
		self::assertSame("developer", $_SESSION[SessionData::class]->getData()->getId());
		self::assertSame(["tea"], $_SESSION["basket"]);
	}

	public function testCustomSessionMustSupplyRegeneration():void {
		$token = new Token(str_repeat("s", 32));
		$data = [SessionData::class => new SessionData($token)];
		try {
			new Authenticator(
				"deployment_" . str_repeat("s", 32), $this->responseUri($token),
				session: new SessionArrayWrapper($data), redirectHandler: $this->redirect(),
			);
			self::fail("Expected a regeneration callback to be required");
		}
		catch(SessionRegenerationException) {}
		self::expectException(\Authwave\NotLoggedInException::class);
		$data[SessionData::class]->getData();
	}

	public function testRotationFailureDoesNotStoreUserOrInvokeCallback():void {
		$token = new Token(str_repeat("s", 32));
		$_SESSION[SessionData::class] = new SessionData($token);
		$called = false;
		try {
			new Authenticator(
				"deployment_" . str_repeat("s", 32), $this->responseUri($token),
				redirectHandler: $this->redirect(),
				onAuthenticated: function() use (&$called):void { $called = true; },
				regenerateSession: static function():void { throw new SessionRegenerationException(); },
			);
			self::fail("Expected rotation to fail");
		}
		catch(SessionRegenerationException) {}
		self::assertFalse($called);
		self::expectException(\Authwave\NotLoggedInException::class);
		$_SESSION[SessionData::class]->getData();
	}

	public function testDefaultContainerRequiresActiveNativeSessionForRotation():void {
		$container = new GlobalSessionContainer();
		session_write_close();
		self::expectException(SessionRegenerationException::class);
		$container->regenerate();
	}

	public function testCallbackFailureDoesNotRepeatRotationOrInvocation():void {
		$token = new Token(str_repeat("s", 32));
		$_SESSION[SessionData::class] = new SessionData($token);
		$uri = $this->responseUri($token);
		$oldId = session_id();
		$calls = 0;
		$callback = function() use (&$calls):void {
			$calls++;
			throw new \RuntimeException("Application failed");
		};
		try {
			new Authenticator(
				"deployment_" . str_repeat("s", 32), $uri,
				redirectHandler: $this->redirect(), onAuthenticated: $callback,
			);
		}
		catch(\RuntimeException $exception) {
			self::assertSame("Application failed", $exception->getMessage());
		}
		$newId = session_id();
		self::assertNotSame($oldId, $newId);
		new Authenticator(
			"deployment_" . str_repeat("s", 32), $uri,
			redirectHandler: $this->redirect(), onAuthenticated: $callback,
		);
		self::assertSame($newId, session_id());
		self::assertSame(1, $calls);
	}
}
