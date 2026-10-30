<?php
namespace Authwave\Test;

use Authwave\ResponseData\UserResponseData;
use PHPUnit\Framework\TestCase;

class ResponseDataTest extends TestCase {
	public function testAccessorsReturnConfiguredData():void {
		$sut = new UserResponseData(
			"user-id",
			"person@example.com",
			["role" => "admin"],
			"Welcome",
		);

		self::assertSame("Welcome", $sut->getMessage());
		self::assertSame("admin", $sut->getField("role"));
		self::assertNull($sut->getField("missing"));
		self::assertSame(["role" => "admin"], $sut->getAllFields());
	}
}
