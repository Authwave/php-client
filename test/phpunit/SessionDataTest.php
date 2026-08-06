<?php
namespace Authwave\Test;

use Authwave\NotLoggedInException;
use Authwave\SessionData;
use Authwave\Token;
use Authwave\ResponseData\UserResponseData;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;

#[AllowMockObjectsWithoutExpectations]
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

	public function testAuthenticationCallbackStateDefaultsToFalse():void {
		self::assertFalse((new SessionData())->hasInvokedAuthenticationCallback());
	}

	public function testAuthenticationCallbackStateCanBePersisted():void {
		$sut = new SessionData();

		$sut->markAuthenticationCallbackInvoked();

		self::assertTrue($sut->hasInvokedAuthenticationCallback());
	}
}
