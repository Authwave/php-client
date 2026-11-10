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

`getAuthUser()` provides the read-only `id` and `email` properties. Use the user ID to associate local records with an account, and keep permission checks in the application.

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

Receiving an administrator-created user
--------------------------------------

Construct `Authenticator` as usual, passing the current URI including its query
string. It automatically recognises `AUTHWAVE_NEW_USER` and `AUTHWAVE_NEW_USER_IV`
in the query string, validates and decrypts the payload, and exposes the identity through
`isLoggedIn()` and `getAuthUser()` for this server-to-server request. The existing
`onAuthenticated` callback also runs, just as it does after browser login.

Your existing user creation/update code can therefore stay in that callback or
in the normal application flow that reads `getAuthUser()`. Upsert by Authwave user
ID so repeated deliveries are safe. There is no new route, request parsing, or
additional callback to implement. For example, reuse your existing save handler:

```php
$auth = new Authenticator(
    $clientKey,
    $currentUri,
    session: $session,
    onAuthenticated: $saveUser,
);
```

The notification does not require a pending login token or write authentication
session data. Existing session data remains unchanged. Normal application code
continues after construction and can persist the returned user in the same way
as during login.

The client adds `Authwave-New-User: received` to the response after validation and
the callback complete. The provider accepts delivery only when the final response
is 2xx and contains that header. A normal HTML response from an older client has
no acknowledgement; an application error returning 5xx is also a failed delivery.
There is no special HTTP status or response body for the application to produce.

The provider makes a GET request to the existing client login URL. The
`AUTHWAVE_NEW_USER` parameter contains the ciphertext and `AUTHWAVE_NEW_USER_IV`
contains the public IV. Both are URL-encoded, preserving base64 characters such as
`+`. Authenticator removes both parameters from its stored URI before invoking the
application callback. No request body or access to superglobals is needed.
The authenticated encrypted payload contains:

```php
[
    "action" => "user-created",
    "deploymentId" => $deploymentId,
    "issuedAt" => time(),
    "id" => $userId,
    "email" => $email,
]
```

The existing deployment secret authenticates the message; the public IV is fresh
for every attempt. The client rejects the wrong action/deployment, tampering,
invalid identities, and timestamps older than five minutes or more than thirty
seconds ahead. The time bounds are `Token::NEW_USER_MAX_AGE` and
`Token::NEW_USER_CLOCK_SKEW`, in seconds. Passwords are never included. Use HTTPS
in production.


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
