--TEST--
CURLOPT_OPENSOCKETFUNCTION: a callback capturing its own handle is collectable
--EXTENSIONS--
curl
curl_hardening
--FILE--
<?php
/* The handle holds the callback through the extension, the callback holds the
 * handle through `use`: only the cycle collector can reclaim that, and only if
 * the extension reports the edge it adds. */
gc_collect_cycles();

$ch = curl_init('http://127.0.0.1:1/');
curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, function () use ($ch): ?CurlSocket {
    return new CurlSocket();
});
$handle = WeakReference::create($ch);
unset($ch);

var_dump($handle->get() !== null);
gc_collect_cycles();
var_dump($handle->get() === null);

/* The same cycle, the callback being shared with a copy that outlives it:
 * collecting the source must not release the callback from under the copy. */
$server = stream_socket_server('tcp://127.0.0.1:0');
$port = (int) explode(':', stream_socket_get_name($server, false))[1];

$ch = curl_init("http://127.0.0.1:{$port}/");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT_MS, 500);
curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, function () use ($ch): ?CurlSocket {
    return null;
});
$copy = curl_copy_handle($ch);
unset($ch);
gc_collect_cycles();

curl_exec($copy);
var_dump(curl_errno($copy) === CURLE_COULDNT_CONNECT);

echo "Done\n";
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
Done
