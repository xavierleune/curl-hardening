--TEST--
CURLOPT_OPENSOCKETFUNCTION: what the callback is told about the endpoint
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
/* No listener is needed: the callback runs before connect(). Proxies from the
 * environment are ignored, or the callback would see the proxy instead. */
function probe(string $url, array $options = []): void {
    $ch = curl_init($url);
    curl_setopt_array($ch, $options + [CURLOPT_RETURNTRANSFER => true, CURLOPT_PROXY => '']);
    curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, function (CurlHandle $h, CurlAddressFamily $family, string $address, ?int $port): bool {
        var_dump($family, $address, $port);
        return false;
    });
    curl_exec($ch);
}

echo "IPv4\n";
probe('http://127.0.0.1:8080/');

echo "\nIPv6\n";
probe('http://[::1]:8080/');

/* An IPv4-mapped IPv6 address reaches IPv4 from an AF_INET6 socket: the family
 * is IpV6 while the host is IPv4. A policy must look at the address. */
echo "\nIPv4-mapped IPv6\n";
probe('http://[::ffff:127.0.0.1]:8080/');

echo "\nUNIX domain socket: the path, and a null port\n";
probe('http://localhost/', [CURLOPT_UNIX_SOCKET_PATH => '/tmp/curl-hardening-does-not-exist.sock']);

echo "\nCurlAddressFamily\n";
var_dump(array_map(fn ($c) => $c->name, CurlAddressFamily::cases()));
var_dump((new ReflectionEnum(CurlAddressFamily::class))->isBacked());

echo "Done\n";
?>
--EXPECT--
IPv4
enum(CurlAddressFamily::IpV4)
string(9) "127.0.0.1"
int(8080)

IPv6
enum(CurlAddressFamily::IpV6)
string(3) "::1"
int(8080)

IPv4-mapped IPv6
enum(CurlAddressFamily::IpV6)
string(16) "::ffff:127.0.0.1"
int(8080)

UNIX domain socket: the path, and a null port
enum(CurlAddressFamily::Unix)
string(39) "/tmp/curl-hardening-does-not-exist.sock"
NULL

CurlAddressFamily
array(3) {
  [0]=>
  string(4) "IpV4"
  [1]=>
  string(4) "IpV6"
  [2]=>
  string(4) "Unix"
}
bool(false)
Done
