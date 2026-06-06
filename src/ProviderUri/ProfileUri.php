<?php
namespace Authwave\ProviderUri;

use Authwave\Token;

class ProfileUri extends BaseProviderUri {
	public function __construct(
		Token $token,
		string $uuid,
		string $currentPath,
		string $baseRemoteUri
	) {
		$baseRemoteUri = $this->normaliseBaseUri($baseRemoteUri);
		parent::__construct($baseRemoteUri);
		$this->path = "/profile/";
		$this->query = $this->buildQuery($token, $uuid);
	}
}
