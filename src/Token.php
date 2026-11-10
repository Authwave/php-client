<?php
namespace Authwave;

use Authwave\ResponseData\BaseResponseData;
use Authwave\ResponseData\UserResponseData;
use GT\Cipher\CipherText;
use GT\Cipher\InitVector;
use GT\Cipher\Key;
use GT\Cipher\Message\EncryptedMessage;
use GT\Cipher\Message\PlainTextMessage;

class Token {
	const USER_CHANGE_MAX_AGE = 300;
	const USER_CHANGE_CLOCK_SKEW = 30;

	private Key $key;
	private InitVector $secretSessionIv;
	private InitVector $iv;
	private ?string $requestPlaintext;

	public function __construct(
		string $secret,
		?InitVector $sessionIv = null,
		?InitVector $iv = null,
	) {
		$this->key = new Key($secret);
		$this->requestPlaintext = null;
		$this->secretSessionIv = $sessionIv ?? new InitVector();
		$this->iv = $iv ?? new InitVector();
	}

	public function __wakeup():void {
		// Older sessions cannot tell us which plaintext has already used this nonce.
		if(!array_key_exists("requestPlaintext", get_object_vars($this))) {
			$this->requestPlaintext = "";
		}
	}

	public function getIv():InitVector {
		return $this->iv;
	}

	public function getSecretIv():InitVector {
		return $this->secretSessionIv;
	}

	/**
	 * The request cipher is sent to the remote provider in the querystring.
	 * It consists of the token's secret IV, encrypted with the client key,
	 * along with an optional message. The secret IV is required for two-way
	 * encryption. The remote provider will decrypt the secret and use it as
	 * the key if encrypting a response cipher, which will be sent back to
	 * the client application in the querystring.
	 */
	public function generateRequestCipher(string $message = ""):CipherText {
		$plaintext = $message . "&secretIv=" . $this->getSecretIv();
		if(!is_null($this->requestPlaintext) && $this->requestPlaintext !== $plaintext) {
			throw new TokenReuseException("Create a new token for a different request.");
		}
		$cipher = (new PlainTextMessage($plaintext, $this->getIv()))->encrypt($this->key);
		$this->requestPlaintext = $plaintext;
		return $cipher;
	}
// The response cipher is send from the remote provider back to the client
// application after a successful authentication and includes a serialised
// UserData object, encrypted using the secret IV, which was created when
// encrypting the original request cipher.

	public function decodeUserChange(string $cipher, string $iv, string $deploymentId, string $action):AuthUser {
		$bytes = base64_decode($iv, true);

		if($bytes === false || strlen($bytes) !== SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
			throw new InvalidUserDataSerializationException("Invalid user change IV.");
		}

		$vector = (new InitVector())->withBytes($bytes);
		$message = new EncryptedMessage($cipher, $vector);
		$decrypted = $message->decrypt($this->key);
		$data = json_decode((string)$decrypted);
		$this->validateUserChange($data, $deploymentId, $action);

		return new AuthUser($data->id, $data->email);
	}

	private function validateUserChange(mixed $data, string $deploymentId, string $action):void {
		if(!is_object($data)
		|| !isset($data->id, $data->email, $data->issuedAt)
		|| !is_string($data->id) || trim($data->id) === ""
		|| !is_string($data->email) || trim($data->email) === ""
		|| !is_int($data->issuedAt)) {
			throw new InvalidUserDataSerializationException("Invalid user change data.");
		}

		if(($data->action ?? null) !== $action
		|| ($data->deploymentId ?? null) !== $deploymentId) {
			throw new InvalidUserDataSerializationException("Unexpected notification action or deployment.");
		}

		$now = time();

		if($data->issuedAt < $now - self::USER_CHANGE_MAX_AGE
		|| $data->issuedAt > $now + self::USER_CHANGE_CLOCK_SKEW) {
			throw new InvalidUserDataSerializationException("User change notification is outside its time window.");
		}
	}

	public function decode(string $base64cipher):BaseResponseData {
		$encryptedMessage = new EncryptedMessage(
			$base64cipher,
			$this->iv,
		);
		$decrypted = $encryptedMessage->decrypt($this->key);

		$data = json_decode((string)$decrypted);
		if(!is_object($data)
		|| !isset($data->email)
		|| !is_string($data->email)
		|| (!isset($data->uuid) && !isset($data->id))) {
			throw new InvalidUserDataSerializationException();
		}

		$id = $data->uuid ?? $data->id;
		if(!is_string($id)) {
			throw new InvalidUserDataSerializationException();
		}

		return new UserResponseData(
			$id,
			$data->email,
		);
	}
}
