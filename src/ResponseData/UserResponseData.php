<?php
namespace Authwave\ResponseData;

use Authwave\InvalidUserDataSerializationException;

class UserResponseData extends BaseResponseData {
	public function __construct(
		private readonly string $uuid,
		private readonly string $email,
		?string $message = null,
	) {
		parent::__construct($message);
	}

	public static function fromJson(string $json):self {
		$data = json_decode($json);
		if(!is_object($data) || !isset($data->email) || !is_string($data->email)) {
			throw new InvalidUserDataSerializationException();
		}
		$id = $data->uuid ?? $data->id ?? null;
		if(!is_string($id)) {
			throw new InvalidUserDataSerializationException();
		}
		return new self($id, $data->email);
	}

	public function getId():string {
		return $this->uuid;
	}

	public function getEmail():string {
		return $this->email;
	}

}
