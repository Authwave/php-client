<?php
namespace Authwave\Test;

use Authwave\NotLoggedInException;
use Authwave\SessionData;
use Authwave\Token;
use Authwave\ResponseData\UserResponseData;
use PHPUnit\Framework\TestCase;

class SessionDataTest extends TestCase {
	public function testGetTokenNull() {
		$sut = new SessionData();
		self::expectException(NotLoggedInException::class);
		$sut->getToken();
	}

	public function testGetToken() {
		$token = self::createMock(Token::class);
		$sut = new SessionData($token);
		self::assertSame($token, $sut->getToken());
	}

	public function testGetUserDataNull() {
		$sut = new SessionData();
		self::expectException(NotLoggedInException::class);
		$sut->getData();
	}

	public function testGetUserData() {
		$token = self::createMock(Token::class);
		$userData = self::createMock(UserResponseData::class);
		$sut = new SessionData($token, $userData);
		self::assertSame($userData, $sut->getData());
	}
}
