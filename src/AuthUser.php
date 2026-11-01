<?php
namespace Authwave;

class AuthUser {
	public function __construct(
		public readonly string $id,
		public readonly string $email,
	) {}
}
