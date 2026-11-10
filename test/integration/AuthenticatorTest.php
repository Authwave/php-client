<?php
namespace Authwave\Test\Integration;

use GT\Cipher\{InitVector, Key};
use GT\Cipher\Message\PlainTextMessage;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class AuthenticatorTest extends TestCase {
	private $server;
	private string $address;
	private string $log;

	protected function setUp():void {
		$socket = stream_socket_server("tcp://127.0.0.1:0");
		$this->address = stream_socket_get_name($socket, false);
		fclose($socket);
		$this->log = tempnam(sys_get_temp_dir(), "authwave-client-");
		$this->server = proc_open([PHP_BINARY, "-S", $this->address, __DIR__ . "/fixture/client.php"],
			[["file", "/dev/null", "r"], ["file", $this->log, "a"], ["file", $this->log, "a"]], $pipes);

		for($attempt = 0; $attempt < 100; $attempt++) {
			$connection = @stream_socket_client("tcp://$this->address", $error, $message, 0.01);

			if($connection) {
				fclose($connection);
				return;
			}

			usleep(10000);
		}

		self::fail("Client test server did not start: " . file_get_contents($this->log));
	}

	protected function tearDown():void {
		proc_terminate($this->server);
		proc_close($this->server);
		unlink($this->log);
	}

	#[DataProvider("existingSessions")]
	public function testConstruct_automaticallyExposesTheNewUserAndRunsTheNormalCallback(string $session):void {
		[$status, $headers, $body] = $this->request($this->notification() . "&session=$session");
		self::assertSame(200, $status);
		self::assertContains("Authwave-New-User: received", $headers);
		$data = json_decode($body, flags: JSON_THROW_ON_ERROR);
		self::assertTrue($data->loggedIn);
		self::assertSame("new-user", $data->id);
		self::assertSame("new@example.test", $data->email);
		self::assertSame("new-user", $data->callbackUser);
		self::assertTrue($data->sessionUnchanged);
	}

	public static function existingSessions():iterable {
		yield "no session or pending login" => [""];
		yield "existing session is untouched" => ["existing"];
	}

	#[DataProvider("invalidRequests")]
	public function testConstruct_rejectsInvalidNotificationsWithoutAcknowledgement(string $query):void {
		[$status, $headers] = $this->request($query);
		self::assertSame(400, $status);
		self::assertNotContains("Authwave-New-User: received", $headers);
	}

	public static function invalidRequests():iterable {
		yield ["AUTHWAVE_NEW_USER=invalid"];
		yield ["AUTHWAVE_NEW_USER=invalid&AUTHWAVE_NEW_USER_IV=invalid"];
		yield ["AUTHWAVE_NEW_USER[]=invalid&AUTHWAVE_NEW_USER_IV=invalid"];
		yield ["AUTHWAVE_NEW_USER=invalid&AUTHWAVE_NEW_USER_IV[]=invalid"];
		yield ["AUTHWAVE_NEW_USER=&AUTHWAVE_NEW_USER_IV="];
	}

	public function testConstruct_callbackFailureIsNotAcknowledged():void {
		[$status, $headers] = $this->request($this->notification() . "&failure=callback");
		self::assertSame(500, $status);
		self::assertNotContains("Authwave-New-User: received", $headers);
	}

	public function testConstruct_applicationFailureAfterConstructionRemainsAnHttpFailure():void {
		[$status] = $this->request($this->notification() . "&failure=page");
		self::assertSame(500, $status);
	}

	public function testConstruct_normalRequestsDoNotAcknowledgeNewUsers():void {
		[$status, $headers, $body] = $this->request("");
		self::assertSame(200, $status);
		self::assertNotContains("Authwave-New-User: received", $headers);
		self::assertFalse(json_decode($body)->loggedIn);
	}

	private function notification():string {
		$vector = new InitVector();
		$message = new PlainTextMessage(json_encode([
			"action" => "user-created", "deploymentId" => "DEPLOYMENT_test", "issuedAt" => time(),
			"id" => "new-user", "email" => "new@example.test",
		], JSON_THROW_ON_ERROR), $vector);
		return http_build_query(["AUTHWAVE_NEW_USER" => (string)$message->encrypt(new Key(str_repeat("0", 32))),
			"AUTHWAVE_NEW_USER_IV" => (string)$vector]);
	}

	private function request(string $query):array {
		$context = stream_context_create(["http" => ["method" => "GET",
			"ignore_errors" => true, "follow_location" => 0]]);
		$body = file_get_contents("http://$this->address/?$query", context: $context);
		$headers = http_get_last_response_headers();
		return [(int)explode(" ", $headers[0])[1], $headers, $body];
	}
}
