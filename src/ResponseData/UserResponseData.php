<?php
namespace Authwave\ResponseData;

class UserResponseData extends BaseResponseData {
	public function __construct(
		private readonly string $uuid,
		private readonly string $email,
		private readonly array $kvp = [],
		string $message = null,
	) {
		parent::__construct($message);
	}

	public function getId():string {
		return $this->uuid;
	}

	public function getEmail():string {
		return $this->email;
	}

	public function getField(string $name):?string {
		return $this->kvp[$name] ?? null;
	}

	/** @return array<string, string> */
	public function getAllFields():array {
		return $this->kvp;
	}
}
