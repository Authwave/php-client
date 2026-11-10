<?php
namespace Authwave\Test;

use Authwave\InvalidUserDataSerializationException;
use Authwave\ResponseCipherDecryptionException;
use Authwave\Token;
use Authwave\ResponseData\UserResponseData;
use GT\Cipher\InitVector;
use GT\Cipher\Key;
use GT\Cipher\Message\DecryptionFailureException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;

#[AllowMockObjectsWithoutExpectations]
class TokenTest extends TestCase {
	public function testDecodeNewUser_acceptsAStandaloneProviderMessage():void {
		[$cipher, $iv] = $this->newUserNotification();
		$sut = new Token(str_repeat("0", 32));

		$user = $sut->decodeNewUser($cipher, $iv, "DEPLOYMENT_test");

		self::assertSame("new-user", $user->id);
		self::assertSame("new@example.test", $user->email);
	}

	#[\PHPUnit\Framework\Attributes\DataProvider("invalidNotifications")]
	public function testDecodeNewUser_rejectsMalformedOrUnrelatedNotifications(string $case):void {
		$secret = str_repeat("0", 32);
		$data = ["action" => "user-created", "deploymentId" => "DEPLOYMENT_test", "issuedAt" => time(),
			"id" => "new-user", "email" => "new@example.test"];

		switch($case) {
			case "wrong action":
				$data["action"] = "login";
				break;
			case "wrong deployment":
				$data["deploymentId"] = "DEPLOYMENT_other";
				break;
			case "expired":
				$data["issuedAt"] = time() - 3600;
				break;
			case "future":
				$data["issuedAt"] = time() + 3600;
				break;
			case "timestamp string":
				$data["issuedAt"] = (string)time();
				break;
			case "missing id":
				unset($data["id"]);
				break;
			case "empty id":
				$data["id"] = " ";
				break;
			case "array email":
				$data["email"] = [];
				break;
			case "empty email":
				$data["email"] = "";
				break;
			case "missing timestamp":
				unset($data["issuedAt"]);
				break;
		}

		$plain = match($case) {
			"bad JSON" => "{",
			"array root" => "[]",
			"null root" => "null",
			default => json_encode($data, JSON_THROW_ON_ERROR),
		};
		[$cipher, $iv] = $this->newUserNotification($plain);
		$sut = new Token($secret);
		$this->expectException(\Authwave\InvalidUserDataSerializationException::class);

		$sut->decodeNewUser($cipher, $iv, "DEPLOYMENT_test");
	}

	public static function invalidNotifications():iterable {
		foreach(["wrong action", "wrong deployment", "expired", "future", "timestamp string", "missing id",
			"empty id", "array email", "empty email", "missing timestamp", "bad JSON", "array root", "null root"] as $case) {
			yield $case => [$case];
		}
	}

	#[\PHPUnit\Framework\Attributes\DataProvider("invalidNotificationEncryption")]
	public function testDecodeNewUser_rejectsInvalidEncryption(string $case):void {
		$secret = str_repeat("0", 32);
		[$cipher, $iv] = $this->newUserNotification();
		$exception = \GT\Cipher\Message\DecryptionFailureException::class;

		if($case === "wrong key") {
			$secret = str_repeat("1", 32);
		}
		elseif($case === "tampered") {
			$bytes = base64_decode($cipher);
			$bytes[0] = chr(ord($bytes[0]) ^ 1);
			$cipher = base64_encode($bytes);
		}
		else {
			$iv = $case === "short IV" ? base64_encode("short") : "!not-base64!";
			$exception = \Authwave\InvalidUserDataSerializationException::class;
		}

		$sut = new Token($secret);
		$this->expectException($exception);

		$sut->decodeNewUser($cipher, $iv, "DEPLOYMENT_test");
	}

	public static function invalidNotificationEncryption():iterable {
		yield ["wrong key"];
		yield ["tampered"];
		yield ["short IV"];
		yield ["invalid IV"];
	}

	/** @return array{string, string} */
	private function newUserNotification(?string $plain = null):array {
		$plain ??= json_encode(["action" => "user-created", "deploymentId" => "DEPLOYMENT_test", "issuedAt" => time(),
			"id" => "new-user", "email" => "new@example.test"], JSON_THROW_ON_ERROR);
		$iv = new InitVector();
		$message = new \GT\Cipher\Message\PlainTextMessage($plain, $iv);
		return [(string)$message->encrypt(new \GT\Cipher\Key(str_repeat("0", 32))), (string)$iv];
	}

	public function testGenerateRequestCipher_sameForSameToken():void {
		$token = new Token(str_repeat("0", 32));

		$cipher1 = $token->generateRequestCipher();
		$cipher2 = $token->generateRequestCipher();

		self::assertEquals($cipher1, $cipher2);
	}

	public function testGenerateRequestCipher_differentForDifferentTokenSameDetails():void {
		$key = str_repeat("0", 32);
		$token1 = new Token($key);
		$token2 = new Token($key);
		$cipher1 = $token1->generateRequestCipher();
		$cipher2 = $token2->generateRequestCipher();

		self::assertNotEquals($cipher1, $cipher2);
	}

	public function testGetIv():void {
		$iv = self::createMock(InitVector::class);
		$sut = new Token("", null, $iv);
		self::assertSame($iv, $sut->getIv());
	}

	public function testDecode_invalidResponseCipher() {
		$key = str_repeat("0", 32);
		$sut = new Token($key);
		self::expectException(DecryptionFailureException::class);
		$sut->decode("not a real cipher");
	}

	public function testDecode_invalidJson() {
		$keyString = str_repeat("0", SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
		$sessionIv = self::createMock(InitVector::class);
		$sessionIv->method("getBytes")
			->willReturn(str_repeat("a", SODIUM_CRYPTO_SECRETBOX_NONCEBYTES));
		$iv = self::createMock(InitVector::class);
		$iv->method("getBytes")
			->willReturn(str_repeat("f", SODIUM_CRYPTO_SECRETBOX_NONCEBYTES));

		$nonce = $iv->getBytes();
		$manualCipherString = sodium_crypto_secretbox(
			"{badly-formed: json]",
			$nonce,
			$keyString,
		);
		$decryptedCipherString = sodium_crypto_secretbox_open($manualCipherString, $nonce, $keyString);

		$base64Cipher = base64_encode($manualCipherString);
		$sut = new Token($keyString, $sessionIv, $iv);
		self::expectException(InvalidUserDataSerializationException::class);
		$sut->decode($base64Cipher);
	}

	public function testDecode_responseCipher() {
		$clientKeyBytes = str_repeat("0", SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
		$ivBytes = str_repeat("1", SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
		$uuid = "abcdef";
		$email = "person@example.com";
		$cipher = sodium_crypto_secretbox(
			json_encode((object)[
				"id" => $uuid,
				"email" => $email,
			]),
			$ivBytes,
			$clientKeyBytes,
		);

		$secretIv = self::createMock(InitVector::class);
		$iv = self::createMock(InitVector::class);
		$iv->method("getBytes")
			->willReturn($ivBytes);

		$sut = new Token($clientKeyBytes, $secretIv, $iv);
		$userData = $sut->decode(base64_encode($cipher));
		self::assertInstanceOf(UserResponseData::class, $userData);
		self::assertEquals($uuid, $userData->getId());
		self::assertEquals($email, $userData->getEmail());
	}

	public function testDecode_invalidIdentityTypes():void {
		$keyBytes = str_repeat("0", SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
		$ivBytes = str_repeat("1", SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
		$cipher = sodium_crypto_secretbox(
			json_encode([
				"id" => 123,
				"email" => "person@example.com",
			]),
			$ivBytes,
			$keyBytes,
		);
		$iv = self::createStub(InitVector::class);
		$iv->method("getBytes")->willReturn($ivBytes);
		$sut = new Token($keyBytes, iv: $iv);

		self::expectException(InvalidUserDataSerializationException::class);
		$sut->decode(base64_encode($cipher));
	}
}
