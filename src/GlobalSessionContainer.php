<?php
namespace Authwave;

use GT\Session\SessionArrayWrapper;

class GlobalSessionContainer extends SessionArrayWrapper {
	/** @SuppressWarnings("PHPMD.Superglobals") */
	public function __construct() {
		if(!isset($_SESSION)) {
			throw new SessionNotStartedException();
		}
		parent::__construct($_SESSION);
	}

	public function regenerate():void {
		if(session_status() !== PHP_SESSION_ACTIVE || headers_sent()) {
			throw new SessionRegenerationException("An active session before output is required.");
		}
		if(!session_regenerate_id(true)) {
			throw new SessionRegenerationException("Could not regenerate the session ID.");
		}
	}
}
