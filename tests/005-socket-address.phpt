--TEST--
CurlSocketAddress: what the callback is told about the endpoint
--EXTENSIONS--
curl
curl_hardening
--SKIPIF--
<?php
/* The IPv6 probes rely on libcurl attempting a literal ::1 address, which it
 * will not do without a usable IPv6 loopback. */
$s = @stream_socket_server('tcp://[::1]:0', $errno, $errstr);
if ($s === false) die('skip no IPv6 loopback available');
fclose($s);
if (PHP_OS_FAMILY === 'Windows') die('skip UNIX domain sockets');
?>
--FILE--
<?php
/* No listener is needed: the callback runs before connect(). */
function probe(string $url, array $options = []): void {
    $ch = curl_init($url);
    curl_setopt_array($ch, $options + [CURLOPT_RETURNTRANSFER => true]);
    curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, function (CurlHandle $h, int $p, CurlSocketAddress $address): ?CurlSocket {
        var_dump($address->family, $address->address, $address->port);
        return null;
    });
    curl_exec($ch);
}

echo "IPv6\n";
probe('http://[::1]:8080/');

/* An IPv4-mapped IPv6 address reaches IPv4 from an AF_INET6 socket: the family
 * is IpV6 while the host is IPv4. A policy must look at the address. */
echo "\nIPv4-mapped IPv6\n";
probe('http://[::ffff:127.0.0.1]:8080/');

echo "\nUNIX domain socket: the path, and no port\n";
probe('http://localhost/', [CURLOPT_UNIX_SOCKET_PATH => '/tmp/curl-hardening-does-not-exist.sock']);

echo "\nNot constructible, readonly, not serializable\n";
try {
    new CurlSocketAddress();
} catch (Error $e) {
    echo $e->getMessage(), "\n";
}
$rc = new ReflectionClass(CurlSocketAddress::class);
var_dump($rc->isFinal(), $rc->isReadOnly());
var_dump(array_map(fn ($c) => $c->name, CurlAddressFamily::cases()));

$ch = curl_init('http://127.0.0.1:1/');
curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, function (CurlHandle $h, int $p, CurlSocketAddress $address): ?CurlSocket {
    try {
        $address->port = 1;
    } catch (Error $e) {
        echo $e->getMessage(), "\n";
    }
    try {
        serialize($address);
    } catch (Exception $e) {
        echo $e->getMessage(), "\n";
    }
    return null;
});
curl_exec($ch);

echo "Done\n";
?>
--EXPECT--
IPv6
enum(CurlAddressFamily::IpV6)
string(3) "::1"
int(8080)

IPv4-mapped IPv6
enum(CurlAddressFamily::IpV6)
string(16) "::ffff:127.0.0.1"
int(8080)

UNIX domain socket: the path, and no port
enum(CurlAddressFamily::Unix)
string(39) "/tmp/curl-hardening-does-not-exist.sock"
int(0)

Not constructible, readonly, not serializable
Call to private CurlSocketAddress::__construct() from global scope
bool(true)
bool(true)
array(3) {
  [0]=>
  string(4) "IpV4"
  [1]=>
  string(4) "IpV6"
  [2]=>
  string(4) "Unix"
}
Cannot modify readonly property CurlSocketAddress::$port
Serialization of 'CurlSocketAddress' is not allowed
Done
