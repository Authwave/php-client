<?php
namespace Authwave;

use Psr\Http\Message\UriInterface;

/** @codeCoverageIgnore */
class RedirectHandler {
	/** @SuppressWarnings("PHPMD.ExitExpression") */
	public function redirect(UriInterface $uri, int $code = 303):void {
		header("Location: $uri", true, $code);
		// phpcs:ignore Generic.PHP.ForbiddenFunctions.Found
		exit;
	}
}
