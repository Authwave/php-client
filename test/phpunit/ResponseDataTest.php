<?php
namespace Authwave\Test;

use Authwave\ResponseData\UserResponseData;
use PHPUnit\Framework\TestCase;

class ResponseDataTest extends TestCase {
	public function testAccessorsReturnConfiguredData():void {
		$sut = new UserResponseData(
			"user-id",
			"person@example.com",
			"Welcome",
		);

		self::assertSame("user-id", $sut->getId());
		self::assertSame("person@example.com", $sut->getEmail());
		self::assertSame("Welcome", $sut->getMessage());
	}
}
