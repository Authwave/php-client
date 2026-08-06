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
	private Key $key;
	private InitVector $secretSessionIv;
	private InitVector $iv;

	public function __construct(
		string $secret,
		?InitVector $sessionIv = null,
		?InitVector $iv = null,
	) {
		$this->key = new Key($secret);
		$this->secretSessionIv = $sessionIv ?? new InitVector();
		$this->iv = $iv ?? new InitVector();
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
// TODO: $message should probably always be a KVP, so we can build up the querystring message here without concatenating.
		$plainTextMessage = new PlainTextMessage($message . "&secretIv=" . $this->getSecretIv(), $this->getIv());
		return $plainTextMessage->encrypt($this->key);
	}
// The response cipher is send from the remote provider back to the client
// application after a successful authentication and includes a serialised
// UserData object, encrypted using the secret IV, which was created when
// encrypting the original request cipher.

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
		$fields = $data->fields ?? [];
		if(!is_string($id) || !is_array($fields)) {
			throw new InvalidUserDataSerializationException();
		}

		return new UserResponseData(
			$id,
			$data->email,
			$fields,
		);
	}
}
