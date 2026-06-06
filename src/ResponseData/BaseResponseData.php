<?php
namespace Authwave\ResponseData;

abstract class BaseResponseData {
	protected ?string $message;

	public function __construct(string $message = null) {
		$this->message = $message;
	}

	public function getMessage():?string {
		return $this->message;
	}
}
