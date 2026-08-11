<?php
namespace Authwave;

use Authwave\ProviderUri\BaseProviderUri;
use Authwave\ProviderUri\AdminUri;
use Authwave\ProviderUri\LoginUri;
use Authwave\ProviderUri\LogoutUri;
use Authwave\ProviderUri\ProfileUri;
use Authwave\ResponseData\UserResponseData;
use Gt\Cipher\InitVector;
use Gt\Cipher\Key;
use Gt\Cipher\Message\EncryptedMessage;
use Gt\Cipher\Message\PlainTextMessage;
use Gt\Http\Uri;
use Gt\Logger\Log;
use Gt\Session\SessionContainer;
use Psr\Http\Message\UriInterface;

class Authenticator {
	const SESSION_STORE_KEY = "AUTHWAVE_CONSUMER_SESSION";
	const RESPONSE_QUERY_PARAMETER = "AUTHWAVE_RESPONSE_DATA";
	const FAKE_EMAIL = "fakelogin@authwave.com";

	private SessionData $sessionData;
	private User $user;
	private Uri $currentUri;
	private readonly string $deploymentId;
	private readonly string $secret;

	public function __construct(
		string $clientKey,
		string|Uri $currentUri,
		private readonly string $authwaveHost = "login.authwave.com",
		private ?SessionContainer $session = null,
		private ?RedirectHandler $redirectHandler = null,
	) {
		$this->deploymentId = substr($clientKey, 0, strrpos($clientKey, "_"));
		$this->secret = substr(strrchr($clientKey, "_"), 1);

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
						$responseData->getAllFields(),
					);
				}
			}
			catch(NotLoggedInException) {}
		}

		if(is_string($currentUri)) {
			$currentUri = new Uri($currentUri);
		}
		$this->currentUri = $currentUri;

		$this->completeAuth();
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

		$this->sessionData = new SessionData(
			$token,
			null,
			$this->currentUri->getQuery() ?: null,
		);
		$this->session->set(SessionData::class, $this->sessionData);
		$this->redirectHandler->redirect($this->getLoginUri($token));
	}

	public function logout(
		null|string|UriInterface $redirectTo = null,
		null|Token $token = null,
	):void {
// TODO: Log out needs implementing - ApplicationDeploymentNotFoundException throws!
		if(is_null($token)) {
			$token = new Token($this->secret);
		}

		if(isset($this->user) && $this->user->email === self::FAKE_EMAIL) {
			$this->session->remove(SessionData::class);
			unset($this->user);
		}
		else {
			$this->sessionData = new SessionData($token);
			$this->session->set(SessionData::class, $this->sessionData);
			$this->session->remove(SessionData::class);
			$this->redirectHandler->redirect(
				$this->getLogoutUri(
					$token,
					is_null($redirectTo)
						? null
						: $this->resolveLogoutRedirect($redirectTo),
				)
			);
		}
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
		if($currentQuery = $this->currentUri->getQuery()) {
			$queryString .= "&";
			$queryString .= $currentQuery;
		}
		$uri = new Uri("$redirectTo?$queryString");
		$this->redirectHandler->redirect($uri);
	}

	public function getUser():User {
		if(!isset($this->user)) {
			throw new NotLoggedInException();
		}

		return $this->user;
	}

	public function getLoginUri(Token $token):BaseProviderUri {
		return new LoginUri(
			$token,
			$this->currentUri,
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
			(string)$this->currentUri,
			$this->deploymentId,
			$this->authwaveHost,
			$redirectTo,
		);
	}

	private function resolveLogoutRedirect(
		string|UriInterface|null $redirectTo,
	):UriInterface {
		if(is_null($redirectTo)) {
			return $this->currentUri;
		}

		if(is_string($redirectTo) && str_starts_with($redirectTo, "?")) {
			return $this->currentUri->withQuery(substr($redirectTo, 1));
		}

		return is_string($redirectTo)
			? new Uri($redirectTo)
			: $redirectTo;
	}

	public function getAdminUri():UriInterface {
		return new AdminUri($this->authwaveHost);
	}

	public function getProfileUri(Token $token = null):UriInterface {
		if(is_null($token)) {
			$token = new Token($this->secret);
		}

		return new ProfileUri(
			$token,
			$this->user->id,
			$this->currentUri,
			$this->authwaveHost
		);
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
			$data->{"kvp"} ?? [],
		);

		$this->session->set(
			SessionData::class,
			new SessionData($token, $userData)
		);

		$this->tidyResponseData($returnQuery);
	}

	private function tidyResponseData(?string $returnQuery = null):void {
		$redirectUri = new Uri($this->currentUri);
		if(!is_null($returnQuery)) {
			$redirectUri = $redirectUri->withQuery($returnQuery);
		}

		$this->redirectHandler->redirect(
			$redirectUri->withoutQueryValue(self::RESPONSE_QUERY_PARAMETER)
		);
	}

	private function getQueryData():?string {
		$queryString = parse_url(
			$this->currentUri,
			PHP_URL_QUERY
		);
		if(!$queryString) {
			return null;
		}

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
