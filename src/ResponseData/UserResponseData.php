<?php
namespace Authwave\ResponseData;

class UserResponseData extends BaseResponseData {
	public function __construct(
		private readonly string $uuid,
		private readonly string $email,
		?string $message = null,
	) {
		parent::__construct($message);
	}

	public function getId():string {
		return $this->uuid;
	}

	public function getEmail():string {
		return $this->email;
	}

}
