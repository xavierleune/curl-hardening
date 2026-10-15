--TEST--
CurlSocket::bind(): choosing the local end of an allowed connection
--EXTENSIONS--
curl
curl_hardening
--FILE--
<?php
$server = stream_socket_server('tcp://127.0.0.1:0');
$port = (int) explode(':', stream_socket_get_name($server, false))[1];

function attempt(int $port, callable $callback, array $options = []): CurlHandle {
    $ch = curl_init("http://127.0.0.1:{$port}/");
    curl_setopt_array($ch, $options + [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT_MS => 500]);
    curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, $callback);
    curl_exec($ch);
    return $ch;
}

$bindTo = fn (string $address, int $p = 0) => function () use ($address, $p): CurlSocket {
    $socket = new CurlSocket();
    $socket->bind($address, $p);
    return $socket;
};

echo "Binding the local end\n";
$ch = attempt($port, $bindTo('127.0.0.1'));
var_dump(curl_errno($ch) === CURLE_OPERATION_TIMEDOUT, curl_getinfo($ch, CURLINFO_LOCAL_IP));

echo "\nA bind that does not match the address family refuses that attempt only\n";
$ch = attempt($port, $bindTo('::1'));
var_dump(curl_errno($ch) === CURLE_COULDNT_CONNECT);

echo "\nThe address is validated when bind() is called\n";
foreach ([['not-an-ip', 0], ["127.0.0.1\0evil", 0], ['127.0.0.1', 65536], ['127.0.0.1', -1]] as [$address, $p]) {
    try {
        (new CurlSocket())->bind($address, $p);
    } catch (ValueError $e) {
        echo $e->getMessage(), "\n";
    }
}

echo "\nbind() cannot be combined with the options libcurl binds with\n";
foreach ([CURLOPT_INTERFACE => '127.0.0.1', CURLOPT_LOCALPORT => 45123] as $option => $value) {
    try {
        attempt($port, $bindTo('127.0.0.1'), [$option => $value]);
    } catch (Error $e) {
        echo $e->getMessage(), "\n";
    }
}

echo "\n... which a copy inherits, and curl_reset() clears\n";
$ch = curl_init("http://127.0.0.1:{$port}/");
curl_setopt($ch, CURLOPT_INTERFACE, '127.0.0.1');
$copy = curl_copy_handle($ch);
curl_setopt_array($copy, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT_MS => 500, CURLOPT_OPENSOCKETFUNCTION => $bindTo('127.0.0.1')]);
try {
    curl_exec($copy);
} catch (Error $e) {
    echo "copy: ", $e->getMessage(), "\n";
}
curl_reset($ch);
curl_setopt_array($ch, [CURLOPT_URL => "http://127.0.0.1:{$port}/", CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT_MS => 500, CURLOPT_OPENSOCKETFUNCTION => $bindTo('127.0.0.1')]);
curl_exec($ch);
var_dump(curl_errno($ch) === CURLE_OPERATION_TIMEDOUT);

echo "\nA CurlSocket holds no descriptor: it can be reused and cloned\n";
$socket = new CurlSocket();
$socket->bind('127.0.0.1');
$shared = clone $socket;
foreach ([1, 2] as $n) {
    $ch = attempt($port, fn (): CurlSocket => $shared);
    var_dump(curl_getinfo($ch, CURLINFO_LOCAL_IP));
}

echo "Done\n";
?>
--EXPECT--
Binding the local end
bool(true)
string(9) "127.0.0.1"

A bind that does not match the address family refuses that attempt only
bool(true)

The address is validated when bind() is called
CurlSocket::bind(): Argument #1 ($address) must be a valid IPv4 or IPv6 address
CurlSocket::bind(): Argument #1 ($address) must be a valid IPv4 or IPv6 address
CurlSocket::bind(): Argument #2 ($port) must be between 0 and 65535
CurlSocket::bind(): Argument #2 ($port) must be between 0 and 65535

bind() cannot be combined with the options libcurl binds with
CurlSocket::bind() cannot be used on a handle that sets CURLOPT_INTERFACE or CURLOPT_LOCALPORT
CurlSocket::bind() cannot be used on a handle that sets CURLOPT_INTERFACE or CURLOPT_LOCALPORT

... which a copy inherits, and curl_reset() clears
copy: CurlSocket::bind() cannot be used on a handle that sets CURLOPT_INTERFACE or CURLOPT_LOCALPORT
bool(true)

A CurlSocket holds no descriptor: it can be reused and cloned
string(9) "127.0.0.1"
string(9) "127.0.0.1"
Done
