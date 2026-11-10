--TEST--
CURLOPT_OPENSOCKETFUNCTION: curl_setopt() and curl_setopt_array() edge cases behave as in ext/curl
--EXTENSIONS--
curl
curl_hardening
--FILE--
<?php
function refused(CurlHandle $ch): bool {
    curl_exec($ch);
    return curl_errno($ch) === CURLE_COULDNT_CONNECT;
}

function handle(): CurlHandle {
    $ch = curl_init('http://127.0.0.1:1/');
    curl_setopt($ch, CURLOPT_PROXY, '');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    return $ch;
}

echo "An exception from an error handler does not stop the options that follow\n";
set_error_handler(function (int $no, string $message): never {
    throw new ErrorException($message, 0, $no);
});
$ch = handle();
try {
    curl_setopt_array($ch, [
        CURLOPT_SSL_VERIFYHOST => 1,
        CURLOPT_OPENSOCKETFUNCTION => fn (): bool => false,
    ]);
} catch (ErrorException $e) {
    echo $e->getMessage(), "\n";
}
restore_error_handler();
var_dump(refused($ch));

echo "\nA reference is followed\n";
$cb = fn (): bool => false;
$ch = handle();
var_dump(curl_setopt_array($ch, [CURLOPT_OPENSOCKETFUNCTION => &$cb]));
var_dump(refused($ch));
$cb = null;
var_dump(curl_setopt_array($ch, [CURLOPT_OPENSOCKETFUNCTION => &$cb]));

echo "\nA numeric string designates the option in coercive mode\n";
$ch = handle();
var_dump(curl_setopt($ch, (string) CURLOPT_OPENSOCKETFUNCTION, fn (): bool => false));
var_dump(refused($ch));

echo "\ncurl_close() is refused from the callback\n";
$ch = handle();
curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, function (CurlHandle $handle): bool {
    try {
        curl_close($handle);
    } catch (Error $e) {
        echo $e->getMessage(), "\n";
    }
    return false;
});
var_dump(@refused($ch));

echo "\nAn invalid option reported by ext/curl adds no frame to the trace\n";
try {
    curl_setopt_array(handle(), ['bogus' => 1, CURLOPT_OPENSOCKETFUNCTION => null]);
} catch (ValueError $e) {
    echo $e->getMessage(), "\n", count($e->getTrace()), "\n";
}
?>
--EXPECT--
An exception from an error handler does not stop the options that follow
curl_setopt_array(): CURLOPT_SSL_VERIFYHOST no longer accepts the value 1, value 2 will be used instead
bool(true)

A reference is followed
bool(true)
bool(true)
bool(true)

A numeric string designates the option in coercive mode
bool(true)
bool(true)

curl_close() is refused from the callback
curl_close(): Attempt to close cURL handle from a callback
bool(true)

An invalid option reported by ext/curl adds no frame to the trace
curl_setopt_array(): Argument #2 ($options) contains an invalid cURL option
1
