<?php
namespace Authwave;

use Closure;
use Authwave\ProviderUri\BaseProviderUri;
use Authwave\ProviderUri\AdminUri;
use Authwave\ProviderUri\LoginUri;
use Authwave\ProviderUri\LogoutUri;
use Authwave\ResponseData\UserResponseData;
use GT\Cipher\InitVector;
use GT\Cipher\Key;
use GT\Cipher\Message\EncryptedMessage;
use GT\Cipher\Message\PlainTextMessage;
use GT\Http\Uri;
use Gt\Logger\Log;
use GT\Session\SessionContainer;
use Psr\Http\Message\UriInterface;

class Authenticator {
	const SESSION_STORE_KEY = "AUTHWAVE_CONSUMER_SESSION";
	const RESPONSE_QUERY_PARAMETER = "AUTHWAVE_RESPONSE_DATA";
	const NEW_USER_QUERY_PARAMETER = "AUTHWAVE_NEW_USER";
	const NEW_USER_IV_QUERY_PARAMETER = "AUTHWAVE_NEW_USER_IV";
	const DELETE_USER_QUERY_PARAMETER = "AUTHWAVE_DELETE_USER";
	const DELETE_USER_IV_QUERY_PARAMETER = "AUTHWAVE_DELETE_USER_IV";
	const USER_CHANGE_ACKNOWLEDGEMENT_HEADER = "Authwave-User-Change";
	const FAKE_EMAIL = "fakelogin@authwave.com";

	private SessionData $sessionData;
	private User $user;
	private UriInterface $currentUriPath;
	private ?UriInterface $returnUri = null;
	private readonly ?Closure $onAuthenticated;
	private readonly ?Closure $onDeleted;
	private readonly string $deploymentId;
	private readonly string $secret;

	public function __construct(
		string $clientKey,
		string|UriInterface $currentUriPath,
		private readonly string $authwaveHost = "login.authwave.com",
		private ?SessionContainer $session = null,
		private ?RedirectHandler $redirectHandler = null,
		?callable $onAuthenticated = null,
		?callable $onDeleted = null,
	) {
		$this->onAuthenticated = is_null($onAuthenticated)
			? null
			: $onAuthenticated(...);
		$this->onDeleted = $onDeleted === null
			? null
			: $onDeleted(...);

		$this->deploymentId = substr($clientKey, 0, strrpos($clientKey, "_"));
		$this->secret = substr(strrchr($clientKey, "_"), 1);

		$this->currentUriPath = is_string($currentUriPath) ? new Uri($currentUriPath) : $currentUriPath;

		if($this->completeUserChange()) {
			return;
		}

		$this->session = $this->session ?? new GlobalSessionContainer();
		$this->redirectHandler = $redirectHandler ?? new RedirectHandler();
		if($sessionData = $this->session->get(SessionData::class)) {
			$this->sessionData = $sessionData;

			try {
				$responseData = $this->sessionData->getData();
				if($responseData instanceof UserResponseData) {
					$this->user = new User(
						$responseData->getId(),
						$responseData->getEmail(),
					);
				}
			}
			catch(NotLoggedInException) {}
		}

		$this->completeAuth();
	}

	public function setReturnUri(string $uri):void {
		$this->returnUri = new Uri($uri);
	}

	public function isLoggedIn():bool {
		return isset($this->user);
	}

	public function login(?Token $token = null):void {
		if($this->isLoggedIn()) {
			return;
		}

		if(is_null($token)) {
			Log::debug("Created new CONSUMER token");
			$token = new Token($this->secret);
		}

		$loginUri = $this->getLoginUri($token);
		$this->sessionData = new SessionData(
			$token,
			null,
			($this->returnUri ?? $this->currentUriPath)->getQuery(),
		);
		$this->session->set(SessionData::class, $this->sessionData);
		$this->redirectHandler->redirect($loginUri);
	}

	public function logout(
		null|string|UriInterface $redirectTo = null,
		null|Token $token = null,
	):void {
		$isFakeUser = isset($this->user) && $this->user->email === self::FAKE_EMAIL;
		$this->session->remove(SessionData::class);
		unset($this->user, $this->sessionData);

		if($isFakeUser) {
			return;
		}

		$token ??= new Token($this->secret);
		$redirectTo ??= $this->returnUri;
		$this->redirectHandler->redirect(
			$this->getLogoutUri(
				$token,
				is_null($redirectTo)
					? null
					: $this->resolveLogoutRedirect($redirectTo),
			)
		);
	}

	public function fakeLogin(string $userId, ?string $email = null, string $redirectTo = "/"):void {
		$secretIv = new InitVector();
		$token = new Token($this->secret, $secretIv);
		$sessionData = new SessionData($token);
		$this->session->set(SessionData::class, $sessionData);

		$userData = new UserResponseData(
			$userId,
			$email ?? self::FAKE_EMAIL,
		);

		$this->session->set(
			SessionData::class,
			new SessionData($token, $userData)
		);

		$message = new PlainTextMessage(
			json_encode([
				"id" => $userData->getId(),
				"email" => $userData->getEmail(),
			]),
			$secretIv,
		);

		$cipherText = $message->encrypt(new Key($this->secret));
		$queryString = http_build_query([
			"AUTHWAVE_RESPONSE_DATA" => (string)$cipherText,
		]);
		$uri = new Uri("$redirectTo?$queryString");
		$this->redirectHandler->redirect($uri);
	}

	public function getAuthUser():AuthUser {
		if(!isset($this->user)) {
			throw new NotLoggedInException();
		}

		return $this->user;
	}

	/** @deprecated Use getAuthUser() instead. */
	public function getUser():User {
		trigger_error(
			"Authenticator::getUser() is deprecated; use getAuthUser() instead.",
			E_USER_DEPRECATED,
		);

		if(!isset($this->user)) {
			throw new NotLoggedInException();
		}

		return $this->user;
	}

	public function getLoginUri(Token $token):BaseProviderUri {
		return new LoginUri(
			$token,
			(string)($this->returnUri ?? $this->currentUriPath),
			$this->deploymentId,
			$this->authwaveHost,
		);
	}

	private function getLogoutUri(
		Token $token,
		?UriInterface $redirectTo,
	):BaseProviderUri {
		return new LogoutUri(
			$token,
			(string)($this->returnUri ?? $this->currentUriPath),
			$this->deploymentId,
			$this->authwaveHost,
			$redirectTo,
		);
	}

	private function resolveLogoutRedirect(
		string|UriInterface $redirectTo,
	):UriInterface {
		if(is_string($redirectTo) && str_starts_with($redirectTo, "?")) {
			return $this->currentUriPath->withQuery(substr($redirectTo, 1));
		}

		return is_string($redirectTo)
			? new Uri($redirectTo)
			: $redirectTo;
	}

	public function getAdminUri():UriInterface {
		return new AdminUri($this->authwaveHost);
	}

	/** Reads the incoming HTTP notification before normal session restoration. */
	private function completeUserChange():bool {
		parse_str($this->currentUriPath->getQuery(), $query);

		$queryKey = self::NEW_USER_QUERY_PARAMETER;
		$vectorKey = self::NEW_USER_IV_QUERY_PARAMETER;
		$action = "user-created";

		if(array_key_exists(self::DELETE_USER_QUERY_PARAMETER, $query)) {
			if(array_key_exists(self::NEW_USER_QUERY_PARAMETER, $query)) {
				throw new InvalidUserDataSerializationException("Ambiguous user change notification.");
			}

			$queryKey = self::DELETE_USER_QUERY_PARAMETER;
			$vectorKey = self::DELETE_USER_IV_QUERY_PARAMETER;
			$action = "user-deleted";
		}

		if(!array_key_exists($queryKey, $query)) {
			return false;
		}

		$cipher = $query[$queryKey];
		$vector = $query[$vectorKey] ?? null;

		if(!is_string($cipher) || !is_string($vector)) {
			throw new InvalidUserDataSerializationException("User change notifications require cipher and IV strings.");
		}

		$token = new Token($this->secret);
		$data = $token->decodeUserChange($cipher, $vector, $this->deploymentId, $action);
		$this->currentUriPath = (new Uri((string)$this->currentUriPath))
			->withoutQueryValue($queryKey)
			->withoutQueryValue($vectorKey);

		if($action === "user-deleted") {
			$this->invokeDeletionCallback($data);
		}
		else {
			$this->user = new User($data->id, $data->email);
			$this->onAuthenticated?->__invoke($this->user);
		}

		header(self::USER_CHANGE_ACKNOWLEDGEMENT_HEADER . ": received");

		return true;
	}

	private function invokeDeletionCallback(AuthUser $user):void {
		if($this->onDeleted === null) {
			throw new AuthwaveException("Configure onDeleted to handle user deletion.");
		}

		($this->onDeleted)($user);
	}

	private function completeAuth():void {
		$queryData = $this->getQueryData();

		if(!$queryData) {
			return;
		}

		if(!isset($this->sessionData)) {
			$this->tidyResponseData();
			return;
		}

		$token = $this->sessionData->getToken();
		$returnQuery = $this->sessionData->getReturnQuery();
		$secretSessionIv = $token->getSecretIv();
		$encrypted = new EncryptedMessage($queryData, $secretSessionIv);
		$key = new Key($this->secret);
		$decrypted = $encrypted->decrypt($key);
		$data = json_decode($decrypted);
		$userData = new UserResponseData(
			$data->{"id"},
			$data->{"email"},
		);
		$this->user = new User(
			$userData->getId(),
			$userData->getEmail(),
		);
		$wasInvoked = $this->sessionData
			->hasInvokedAuthenticationCallback();

		$newSessionData = new SessionData($token, $userData, $returnQuery);
		if($wasInvoked || isset($this->onAuthenticated)) {
			$newSessionData->markAuthenticationCallbackInvoked();
		}
		$this->session->set(SessionData::class, $newSessionData);

		if(isset($this->onAuthenticated) && !$wasInvoked) {
			($this->onAuthenticated)($this->user);
		}

		$this->tidyResponseData($returnQuery);
	}

	private function tidyResponseData(?string $returnQuery = null):void {
		$redirectUri = new Uri((string)$this->currentUriPath);
		if(!is_null($returnQuery)) {
			$redirectUri = $redirectUri->withQuery($returnQuery);
		}

		$this->redirectHandler->redirect(
			$redirectUri->withoutQueryValue(self::RESPONSE_QUERY_PARAMETER)
		);
	}

	private function getQueryData():?string {
		$queryString = $this->currentUriPath->getQuery();
		$queryParts = [];
		parse_str($queryString, $queryParts);
		if(empty($queryParts[self::RESPONSE_QUERY_PARAMETER])) {
			return null;
		}

		return strtr(
			$queryParts[self::RESPONSE_QUERY_PARAMETER],
			" ",
			"+",
		);
	}
}
