<?php
namespace Authwave;

use Authwave\ResponseData\BaseResponseData;
use Authwave\ResponseData\UserResponseData;

class SessionData {
	private bool $callbackInvoked = false;

	public function __construct(
		private readonly ?Token $token = null,
		private readonly ?BaseResponseData $data = null,
	) {
	}

	public function getToken():Token {
		if(!isset($this->token)) {
			throw new NotLoggedInException();
		}

		return $this->token;
	}

	public function getData():BaseResponseData {
		if(!isset($this->data)) {
			throw new NotLoggedInException();
		}

		return $this->data;
	}

	public function hasInvokedAuthenticationCallback():bool {
		return $this->callbackInvoked;
	}

	public function markAuthenticationCallbackInvoked():void {
		$this->callbackInvoked = true;
	}
}
