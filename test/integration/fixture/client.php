<?php
require dirname(__DIR__, 3) . "/vendor/autoload.php";

$secret = str_repeat("0", 32);
$callbackUser = null;
$sessionBefore = null;

if(($_GET["session"] ?? "") === "existing") {
	$_SESSION = ["keep" => "preserved", Authwave\SessionData::class => new Authwave\SessionData(
		new Authwave\Token($secret), new Authwave\ResponseData\UserResponseData("existing", "existing@example.test"))];
	$sessionBefore = $_SESSION;
}
elseif(!isset($_GET["AUTHWAVE_NEW_USER"])) {
	$_SESSION = [];
	$sessionBefore = [];
}

try {
	$sut = new Authwave\Authenticator("DEPLOYMENT_test_$secret", $_SERVER["REQUEST_URI"],
		onAuthenticated: function(Authwave\AuthUser $user)use(&$callbackUser):void {
			if(($_GET["failure"] ?? "") === "callback") {
				throw new RuntimeException("Application callback failed");
			}

			$callbackUser = $user->id;
		});

	if(($_GET["failure"] ?? "") === "page") {
		throw new RuntimeException("Application save failed");
	}

	echo json_encode([
		"loggedIn" => $sut->isLoggedIn(),
		"id" => $sut->isLoggedIn() ? $sut->getAuthUser()->id : null,
		"email" => $sut->isLoggedIn() ? $sut->getAuthUser()->email : null,
		"callbackUser" => $callbackUser,
		"sessionUnchanged" => ($_SESSION ?? null) === $sessionBefore,
	], JSON_THROW_ON_ERROR);
}
catch(Authwave\AuthwaveException|GT\Cipher\Message\DecryptionFailureException) {
	http_response_code(400);
}
catch(Throwable) {
	http_response_code(500);
}
