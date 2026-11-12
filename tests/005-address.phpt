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
    curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, function (CurlHandle $h, string $address, int $port): bool {
        var_dump($address, $port);
        return false;
    });
    curl_exec($ch);
}

echo "IPv4\n";
probe('http://127.0.0.1:8080/');

echo "\nIPv6\n";
probe('http://[::1]:8080/');

/* An IPv4-mapped IPv6 address reaches IPv4 from an AF_INET6 socket. */
echo "\nIPv4-mapped IPv6\n";
probe('http://[::ffff:127.0.0.1]:8080/');

echo "\nUNIX domain socket: the path, and port 0\n";
probe('http://localhost/', [CURLOPT_UNIX_SOCKET_PATH => '/tmp/curl-hardening-does-not-exist.sock']);

echo "Done\n";
?>
--EXPECT--
IPv4
string(9) "127.0.0.1"
int(8080)

IPv6
string(3) "::1"
int(8080)

IPv4-mapped IPv6
string(16) "::ffff:127.0.0.1"
int(8080)

UNIX domain socket: the path, and port 0
string(39) "/tmp/curl-hardening-does-not-exist.sock"
int(0)
Done
