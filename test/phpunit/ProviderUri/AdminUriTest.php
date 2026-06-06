<?php
namespace Authwave\Test\ProviderUri;

use Authwave\ProviderUri\AdminUri;
use PHPUnit\Framework\TestCase;

class AdminUriTest extends TestCase {
	public function testPathAccount() {
		$sut = new AdminUri("example.com");
		self::assertEquals(
			"/admin/",
			$sut->getPath()
		);
	}
}
