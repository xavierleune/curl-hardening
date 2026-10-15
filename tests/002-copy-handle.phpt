--TEST--
CURLOPT_OPENSOCKETFUNCTION: curl_copy_handle() and clone
--EXTENSIONS--
curl
curl_hardening
--FILE--
<?php
/* A copy keeps the callback it was copied with, whatever happens to the source
 * afterwards, and the callback receives the copy -- not the source. */
$server = stream_socket_server('tcp://127.0.0.1:0');
$port = (int) explode(':', stream_socket_get_name($server, false))[1];

$calls = [];
$refuse = function (string $name) use (&$calls): Closure {
    return function (CurlHandle $handle) use ($name, &$calls): ?CurlSocket {
        $calls[] = [$name, $handle];
        return null;
    };
};

function run(CurlHandle $ch): bool {
    curl_exec($ch);
    return curl_errno($ch) === CURLE_COULDNT_CONNECT;
}

$a = curl_init("http://127.0.0.1:{$port}/");
curl_setopt($a, CURLOPT_RETURNTRANSFER, true);
curl_setopt($a, CURLOPT_TIMEOUT_MS, 500);
curl_setopt($a, CURLOPT_OPENSOCKETFUNCTION, $refuse('original'));

foreach (['curl_copy_handle' => fn ($h) => curl_copy_handle($h), 'clone' => fn ($h) => clone $h] as $how => $copy) {
    echo "{$how}\n";
    $b = $copy($a);
    $calls = [];
    var_dump(run($b), $calls[0][0], $calls[0][1] === $b);
}

echo "\nRemoving, then replacing, the callback on the source\n";
$b = curl_copy_handle($a);
curl_setopt($a, CURLOPT_OPENSOCKETFUNCTION, null);
curl_setopt($a, CURLOPT_OPENSOCKETFUNCTION, $refuse('replacement'));
$c = clone $a;
$calls = [];
run($b);
run($c);
run($a);
var_dump(array_column($calls, 0));

echo "\nThe source is released before its copies\n";
unset($a);
$calls = [];
var_dump(run($b), run($c), array_column($calls, 0));

echo "Done\n";
?>
--EXPECT--
curl_copy_handle
bool(true)
string(8) "original"
bool(true)
clone
bool(true)
string(8) "original"
bool(true)

Removing, then replacing, the callback on the source
array(3) {
  [0]=>
  string(8) "original"
  [1]=>
  string(11) "replacement"
  [2]=>
  string(11) "replacement"
}

The source is released before its copies
bool(true)
bool(true)
array(2) {
  [0]=>
  string(8) "original"
  [1]=>
  string(11) "replacement"
}
Done
