<?php
namespace Authwave\ProviderUri;

use Authwave\Token;

class LogoutUri extends BaseProviderUri {
	public function __construct(
		Token $token,
		string $currentPath,
		string $deploymentId,
		string $baseRemoteUri = self::DEFAULT_BASE_REMOTE_URI
	) {
		$baseRemoteUri = $this->normaliseBaseUri($baseRemoteUri);
		parent::__construct($baseRemoteUri);
		$this->query = $this->buildQuery(
			$token,
			$deploymentId,
			$currentPath,
			"action=logout",
		);
	}
}
