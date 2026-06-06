<?php
namespace Authwave\ProviderUri;

use Authwave\Token;
use Gt\Http\Uri;

/**
 * The AuthUri class represents the Uri used to redirect the user agent to the
 * Authwave provider in order to initiate authentication. A Token is used to
 * pass the secret IV to the provider, encrypted with the API key. The secret
 * IV is only ever stored in the client's session, and is unique to the session.
 */
class LoginUri extends BaseProviderUri {
	/**
	 * @param Token $token This must be the same instance of the Token when
	 * creating Authenticator for the first time as it is when checking the
	 * response from the Authwave provider (store in a session).
	 * @param string $baseRemoteUri The base URI of the application. This is the
	 * URI authority with optional scheme, as localhost allows http://
	 */
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
			"action=login",
		);
	}
}
