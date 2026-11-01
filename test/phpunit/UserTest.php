<?php
namespace Authwave\Test;

use Authwave\AuthUser;
use Authwave\User;
use PHPUnit\Framework\TestCase;

class UserTest extends TestCase {
	public function testDeprecatedUserIsAnAuthUser():void {
		self::assertInstanceOf(AuthUser::class, new User("user-id", "person@example.com"));
	}
}
