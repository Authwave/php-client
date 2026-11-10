<?php
namespace Authwave\Test\ProviderUri;

use Authwave\InsecureProtocolException;
use Authwave\ProviderUri\AdminUri;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class TestDomainTest extends TestCase {
	public static function providerHosts():array {
		return [
			["http://login.realtest.authwave.test:9090", true],
			["http://app.test", true],
			["http://LOGIN.EXAMPLE.TEST:9090", true],
			["http://login.example.test.:9090", true],
			["http://localhost:9090", true],
			["http://127.0.0.127:9090", true],
			["https://login.authwave.com", true],
			["http://login.realtest.authwave-test:9090", false],
			["http://example.test.attacker.com", false],
			["http://exampletest", false],
			["http://test", false],
			["http://login.authwave.com", false],
			["ftp://example.test", false],
		];
	}

	#[DataProvider("providerHosts")]
	public function testProviderProtocolPolicy(string $host, bool $allowed):void {
		if(!$allowed) {
			self::expectException(InsecureProtocolException::class);
		}
		$uri = new AdminUri($host);
		self::assertSame("/admin/", $uri->getPath());
		if($allowed && str_starts_with($host, "http://")) {
			self::assertSame("http", $uri->getScheme());
		}
		if(str_contains($host, ":9090")) {
			self::assertSame(9090, $uri->getPort());
		}
	}
}
