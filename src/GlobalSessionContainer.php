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
}
