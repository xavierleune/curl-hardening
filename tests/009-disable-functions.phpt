--TEST--
curl_hardening starts and shuts down cleanly when hooked functions are disabled
--EXTENSIONS--
curl
curl_hardening
--INI--
disable_functions=curl_reset,curl_setopt_array,curl_close
--FILE--
<?php
/* disable_functions frees the functions it removes after the polyfill hooked
 * them: shutting down must not write into them. */
var_dump(function_exists('curl_reset'));
$ch = curl_init('http://127.0.0.1:1/');
curl_setopt($ch, CURLOPT_PROXY, '');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
var_dump(curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, fn (): bool => false));
curl_exec($ch);
var_dump(curl_errno($ch) === CURLE_COULDNT_CONNECT);
?>
--EXPECT--
bool(false)
bool(true)
bool(true)
