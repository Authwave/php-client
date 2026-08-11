<?php
namespace Authwave\ProviderUri;

use Authwave\Token;
use Psr\Http\Message\UriInterface;

class LogoutUri extends BaseProviderUri {
	public function __construct(
		Token $token,
		string $currentPath,
		string $deploymentId,
		string $baseRemoteUri = self::DEFAULT_BASE_REMOTE_URI,
		?UriInterface $redirectTo = null,
	) {
		$baseRemoteUri = $this->normaliseBaseUri($baseRemoteUri);
		parent::__construct($baseRemoteUri);
		$message = ["action" => "logout"];
		if(!is_null($redirectTo)) {
			$message["redirectTo"] = (string)$redirectTo;
		}
		$this->query = $this->buildQuery(
			$token,
			$deploymentId,
			$currentPath,
			http_build_query($message),
		);
	}
}
