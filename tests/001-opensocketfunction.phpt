--TEST--
CURLOPT_OPENSOCKETFUNCTION: allowing, refusing, and what the callback receives
--EXTENSIONS--
curl
curl_hardening
--FILE--
<?php
var_dump(CURLOPT_OPENSOCKETFUNCTION, CURLSOCKTYPE_IPCXN);

/* A listening socket that never answers: an allowed attempt connects and then
 * times out, a refused one never reaches connect(). A literal address means a
 * single attempt, whatever the host's dual-stack setup. */
$server = stream_socket_server('tcp://127.0.0.1:0');
$port = (int) explode(':', stream_socket_get_name($server, false))[1];

function handle(int $port): CurlHandle {
    $ch = curl_init("http://127.0.0.1:{$port}/");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT_MS, 500);
    return $ch;
}

echo "\nWhat the callback receives\n";
$ch = handle($port);
var_dump(curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION,
    function (CurlHandle $handle, int $purpose, CurlSocketAddress $address) use (&$ch, $port): ?CurlSocket {
        var_dump($handle === $ch, $purpose === CURLSOCKTYPE_IPCXN);
        var_dump($address->family, $address->address, $address->port === $port);
        return new CurlSocket();
    }));
curl_exec($ch);
var_dump(curl_errno($ch) === CURLE_OPERATION_TIMEDOUT);

echo "\nReturning null refuses the connection\n";
curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, fn (): ?CurlSocket => null);
curl_exec($ch);
var_dump(curl_errno($ch) === CURLE_COULDNT_CONNECT);

echo "\nAny other return value refuses it and raises a TypeError\n";
curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, fn () => true);
try {
    curl_exec($ch);
} catch (TypeError $e) {
    echo $e->getMessage(), "\n";
}

echo "\nAn exception refuses it and propagates\n";
curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, function (): ?CurlSocket {
    throw new RuntimeException('blocked');
});
try {
    curl_exec($ch);
} catch (RuntimeException $e) {
    echo $e->getMessage(), "\n";
}
var_dump(curl_errno($ch) === CURLE_COULDNT_CONNECT);

echo "\nnull removes the callback\n";
curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, fn (): ?CurlSocket => null);
var_dump(curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, null));
curl_exec($ch);
var_dump(curl_errno($ch) === CURLE_OPERATION_TIMEDOUT);

echo "\nInvalid callbacks are reported the way ext/curl reports its own\n";
foreach ([
    fn () => curl_setopt(handle($port), CURLOPT_OPENSOCKETFUNCTION, 42),
    fn () => curl_setopt(handle($port), CURLOPT_OPENSOCKETFUNCTION, 'function_does_not_exist'),
    fn () => curl_setopt_array(handle($port), [CURLOPT_OPENSOCKETFUNCTION => 42]),
] as $call) {
    try {
        $call();
    } catch (TypeError $e) {
        echo get_class($e), ': ', $e->getMessage(), "\n";
    }
}

echo "\nA private method is resolved where the option is set, like ext/curl\n";
final class Policy {
    public function install(CurlHandle $ch): void {
        curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, [$this, 'decide']);
    }
    private function decide(CurlHandle $handle, int $purpose, CurlSocketAddress $address): ?CurlSocket {
        echo "private method called\n";
        return null;
    }
}
$ch = handle($port);
(new Policy())->install($ch);
curl_exec($ch);
var_dump(curl_errno($ch) === CURLE_COULDNT_CONNECT);

echo "Done\n";
?>
--EXPECT--
int(20163)
int(0)

What the callback receives
bool(true)
bool(true)
bool(true)
enum(CurlAddressFamily::IpV4)
string(9) "127.0.0.1"
bool(true)
bool(true)

Returning null refuses the connection
bool(true)

Any other return value refuses it and raises a TypeError
The CURLOPT_OPENSOCKETFUNCTION callback must return a CurlSocket or null

An exception refuses it and propagates
blocked
bool(true)

null removes the callback
bool(true)
bool(true)

Invalid callbacks are reported the way ext/curl reports its own
TypeError: curl_setopt(): Argument #3 ($value) must be a valid callback for option CURLOPT_OPENSOCKETFUNCTION, no array or string given
TypeError: curl_setopt(): Argument #3 ($value) must be a valid callback for option CURLOPT_OPENSOCKETFUNCTION, function "function_does_not_exist" not found or invalid function name
TypeError: curl_setopt_array(): Argument #2 ($options) must be a valid callback for option CURLOPT_OPENSOCKETFUNCTION, no array or string given

A private method is resolved where the option is set, like ext/curl
private method called
bool(true)
Done
