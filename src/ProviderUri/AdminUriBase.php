<?php
namespace Authwave\ProviderUri;

class AdminUriBase extends BaseProviderUri {
	public function __construct(
		string $baseRemoteUri
	) {
		$baseRemoteUri = $this->normaliseBaseUri($baseRemoteUri);
		parent::__construct($baseRemoteUri);
		$this->path = "/admin";
	}
}
