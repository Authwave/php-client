<?php
namespace Authwave\Test\ProviderUri;

use Authwave\InitVector;
use Authwave\InsecureProtocolException;
use Authwave\ProviderUri\LoginUri;
use Authwave\Token;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;

class AbstractProviderUriTest extends TestCase {
	public function testAuthUriHttps() {
		$baseUri = self::createMock(UriInterface::class);
		$baseUri->method("__toString")
			->willReturn("https://example.com");
		$token = self::createMock(Token::class);

		$sut = new LoginUri(
			$token,
			"",
			$baseUri
		);
		self::assertEquals(
			"https",
			$sut->getScheme()
		);
		self::assertNull(
			$sut->getPort()
		);
	}

	public function testAuthUriWithNonStandardPort() {
		$baseUri = self::createMock(UriInterface::class);
		$baseUri->method("__toString")
			->willReturn("http://localhost:8081");
		$token = self::createMock(Token::class);

		$sut = new LoginUri(
			$token,
			"",
			$baseUri
		);
		self::assertEquals(
			"http",
			$sut->getScheme()
		);
		self::assertEquals(
			8081,
			$sut->getPort()
		);
	}

// All AuthUris MUST be served over HTTPS, with the one exception of localhost.
// But it should still default to HTTPS on localhost.
	public function testGetAuthUriHostnameLocalhostHttpsByDefault() {
		$token = self::createMock(Token::class);
		$sut = new LoginUri(
			$token,
			"/",
			"localhost"
		);

		self::assertStringStartsWith(
			"https://localhost",
			$sut
		);
	}

// We should be able to set the scheme to HTTP for localhost hostname only.
	public function testGetAuthUriHostnameLocalhostHttpAllowed() {
		$token = self::createMock(Token::class);
		$sut = new LoginUri(
			$token,
			"/",
			"http://localhost"
		);
		self::assertStringStartsWith(
			"http://localhost",
			$sut
		);
	}

// We should NOT be able to set the scheme to HTTP for other hostnames.
	public function testGetAuthUriHostnameNotLocalhostHttpNotAllowed() {
		$token = self::createMock(Token::class);
		self::expectException(InsecureProtocolException::class);
		new LoginUri(
			$token,
			"/",
			"http://localhost.com"
		);
	}

	public function testAuthUriHttpsInferred() {
		$baseUri = self::createMock(UriInterface::class);
		$baseUri->method("__toString")
			->willReturn("example.com");
// Note on the line above, no scheme is passed in - we must assume https.
		$token = self::createMock(Token::class);

		$sut = new LoginUri(
			$token,
			"/",
			$baseUri);

		self::assertEquals(
			"https",
			$sut->getScheme()
		);
	}
}
