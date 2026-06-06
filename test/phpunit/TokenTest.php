<?php
namespace Authwave\Test;

use Authwave\InvalidUserDataSerializationException;
use Authwave\ResponseCipherDecryptionException;
use Authwave\Token;
use Authwave\ResponseData\UserResponseData;
use Gt\Cipher\InitVector;
use Gt\Cipher\Key;
use Gt\Cipher\Message\DecryptionFailureException;
use PHPUnit\Framework\TestCase;

class TokenTest extends TestCase {
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

	public function testDecrypt_responseCipherInvalid() {
		$key = str_repeat("0", 32);
		$sut = new Token($key);
		self::expectException(DecryptionFailureException::class);
		$sut->decode("not a real cipher");
	}

	public function testDecryptResponseCipherBadJson() {
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

	public function testDecryptResponseCipher() {
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
}
