<?php
namespace Authwave;

class User {
	public function __construct(
		public readonly string $id,
		public readonly string $email,
		private readonly array $kvp = [],
	) {}

	public function getData(string $key):?string {
		return $this->kvp[$key] ?? null;
	}

	public function getKvp():array {
		return $this->kvp;
	}
}
