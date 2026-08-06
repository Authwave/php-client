<?php
namespace Authwave\Test;

use Authwave\AuthUser;
use Authwave\User;
use PHPUnit\Framework\TestCase;

class UserTest extends TestCase {
	public function testKvpAccess():void {
		$sut = new AuthUser("user-id", "person@example.com", ["role" => "admin"]);

		self::assertSame("admin", $sut->getData("role"));
		self::assertNull($sut->getData("missing"));
		self::assertSame(["role" => "admin"], $sut->getKvp());
	}

	public function testDeprecatedUserIsAnAuthUser():void {
		self::assertInstanceOf(AuthUser::class, new User("user-id", "person@example.com"));
	}
}
