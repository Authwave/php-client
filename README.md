PHP client library to implement Authwave in your application
============================================================

Authwave handles authentication through a hosted or self-hosted provider, while this library makes the authenticated user's identity available to a PHP application. The provider presents the login screens; the client manages the encrypted exchange and remembers the user in the application's session.

Register an application deployment with your [Authwave provider](https://github.com/Authwave/provider), configure its client return URI, and keep its complete client key in server-side configuration.

Installation
------------

The client requires PHP 8.4 or later and the Sodium extension.

```bash
composer require authwave/php-client
```

Basic usage
-----------

For a small application served at `/`, the following page shows a login link and greets the authenticated visitor. Set `AUTHWAVE_CLIENT_KEY` in the server environment to the complete provider-issued key, including its deployment identifier and secret.

```php
<?php
use Authwave\Authenticator;
use Authwave\AuthUser;

require __DIR__ . "/vendor/autoload.php";
session_start();

$clientKey = getenv("AUTHWAVE_CLIENT_KEY");
if($clientKey === false || $clientKey === "") {
	throw new RuntimeException("Set AUTHWAVE_CLIENT_KEY before running the application.");
}

$auth = new Authenticator(
	clientKey: $clientKey,
	currentUriPath: $_SERVER["REQUEST_URI"],
	onAuthenticated: function(AuthUser $user):void {
		error_log("Authentication completed for user " . $user->id);
	},
);

if(isset($_GET["login"])) {
	$auth->setReturnUri("/");
	$auth->login();
}

if($auth->isLoggedIn()) {
	$user = $auth->getAuthUser();
	$email = htmlspecialchars($user->email, ENT_QUOTES, "UTF-8");
	echo "<p>You are logged in as <strong>$email</strong>.</p>";
}
else {
	echo '<p><a href="?login">Log in</a></p>';
}
```

Load the autoloader before starting the session, and construct `Authenticator` before sending output. Its constructor processes returning authentication responses and can redirect immediately. Run the same setup on every route that can receive a login response.

`getAuthUser()` provides the read-only `id` and `email` properties, `getData($name)` for an optional custom field, and `getKvp()` for all supplied custom fields. Use the user ID to associate local records with an account, and keep permission checks in the application. The provider's login response supplies ID and email; custom fields may be absent.

The `onAuthenticated` callback runs when a new authentication completes, before the client removes the response parameter with a redirect. It does not run when a user is restored from the session. The callback is marked before invocation and is not retried automatically if it throws.

Login destinations and self-hosting
----------------------------------

Use `setReturnUri()` before login to choose an application path, query string and fragment:

```php
$auth->setReturnUri("/members/orders?status=open#latest");
$auth->login();
```

Without an override, login requests the current URI. The provider accepts root-relative paths and absolute URLs matching the deployment's configured client scheme, host and effective port. Invalid or external destinations fall back to the configured client return URI.

The `authwaveHost` constructor argument selects the provider and defaults to `login.authwave.com`. For a self-hosted provider, supply its scheme, host and optional port, such as `https://login.example.com`.

Logging out
-----------

After the application's normal POST and CSRF checks, call `logout()` before sending output:

```php
$auth->logout("/signed-out");
```

The client clears its stored and in-memory authentication state, preserving unrelated session data, then redirects to the provider to clear its session. An explicit destination takes priority over `setReturnUri()`. Without either setting, the provider uses the deployment's default return location. Relative logout paths are resolved against the deployment's client URI. Keep destinations under application control.

The default redirect handler ends the request. Custom handlers must transfer control appropriately; the authenticator is already logged out when they run. The default development fake user is logged out locally without visiting the provider.

Documentation
-------------

Follow the [quick start guide](https://github.com/Authwave/php-client/wiki/Quick-start-guide) for a complete setup, or browse the [wiki](https://github.com/Authwave/php-client/wiki) for session integration, callbacks, destination rules and the API reference.

Running checks
--------------

From the repository root, install development dependencies and run the configured checks:

```bash
composer install
composer test
```

The test script runs PHPUnit, PHPStan, PHP_CodeSniffer and PHPMD. To run the unit tests alone, use `composer phpunit`.
