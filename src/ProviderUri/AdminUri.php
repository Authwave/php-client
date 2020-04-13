<?php
namespace Authwave\ProviderUri;

class AdminUri extends AbstractProviderUri {
	const PATH_ADMIN = "/admin";
	const PATH_SETTINGS = "/settings";

	public function __construct(
		string $baseRemoteUri,
		string $path
	) {
		$baseRemoteUri = $this->normaliseBaseUri($baseRemoteUri);
		parent::__construct($baseRemoteUri);
		$this->path = $path;
	}
}