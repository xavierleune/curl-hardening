--TEST--
CURLOPT_OPENSOCKETFUNCTION: curl_reset() and curl_setopt_array()
--EXTENSIONS--
curl
curl_hardening
--FILE--
<?php
$server = stream_socket_server('tcp://127.0.0.1:0');
$port = (int) explode(':', stream_socket_get_name($server, false))[1];
$url = "http://127.0.0.1:{$port}/";
$refuse = fn (): ?CurlSocket => null;

echo "curl_reset() removes the callback, like any other option\n";
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, $refuse);
curl_reset($ch);
curl_setopt_array($ch, [CURLOPT_URL => $url, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT_MS => 500]);
curl_exec($ch);
var_dump(curl_errno($ch) === CURLE_OPERATION_TIMEDOUT);

echo "\n... but not from within it, as ext/curl refuses for its own callbacks\n";
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, function (CurlHandle $handle): ?CurlSocket {
    curl_reset($handle);
    return new CurlSocket();
});
try {
    curl_exec($ch);
} catch (Error $e) {
    echo $e->getMessage(), "\n";
}
var_dump(curl_errno($ch) === CURLE_COULDNT_CONNECT);

echo "\ncurl_setopt_array() applies the options in order, around ours\n";
$ch = curl_init();
var_dump(curl_setopt_array($ch, [
    CURLOPT_URL => $url,
    CURLOPT_OPENSOCKETFUNCTION => $refuse,
    CURLOPT_RETURNTRANSFER => true,
]));
var_dump(curl_exec($ch), curl_errno($ch) === CURLE_COULDNT_CONNECT);

echo "\n... and stops at the first failure\n";
$ch = curl_init($url);
try {
    curl_setopt_array($ch, [CURLOPT_OPENSOCKETFUNCTION => 42, CURLOPT_URL => 'http://example.invalid/']);
} catch (TypeError $e) {
    echo $e->getMessage(), "\n";
}
var_dump(curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) === $url);
try {
    curl_setopt_array($ch, [999999 => 1, CURLOPT_OPENSOCKETFUNCTION => $refuse]);
} catch (ValueError $e) {
    echo $e->getMessage(), "\n";
}
curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT_MS => 500]);
curl_exec($ch);
var_dump(curl_errno($ch) === CURLE_OPERATION_TIMEDOUT);

echo "Done\n";
?>
--EXPECTF--
curl_reset() removes the callback, like any other option
bool(true)

... but not from within it, as ext/curl refuses for its own callbacks
curl_reset(): Attempt to reset cURL handle from a callback
bool(true)

curl_setopt_array() applies the options in order, around ours
bool(true)
bool(false)
bool(true)

... and stops at the first failure
curl_setopt_array(): Argument #2 ($options) must be a valid callback for option CURLOPT_OPENSOCKETFUNCTION, no array or string given
bool(true)
curl_setopt_array(): Argument #2 ($options) must contain only valid cURL options
bool(true)
Done
