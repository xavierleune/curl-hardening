--TEST--
CURLOPT_OPENSOCKETFUNCTION still applies to code running during request shutdown
--EXTENSIONS--
curl
curl_hardening
session
--INI--
session.save_handler=files
session.use_cookies=0
session.use_strict_mode=0
--FILE--
<?php
/* ext/session writes the session from its own RSHUTDOWN, which may run after
 * the polyfill's: a write handler doing a transfer must still find its callback,
 * and curl_reset() and curl_setopt() must still work on its handle. */
class Handler implements SessionHandlerInterface
{
    public function __construct(private CurlHandle $ch) {}
    public function open(string $path, string $name): bool { return true; }
    public function close(): bool { return true; }
    public function read(string $id): string|false { return ''; }
    public function destroy(string $id): bool { return true; }
    public function gc(int $max_lifetime): int|false { return 0; }

    public function write(string $id, string $data): bool
    {
        var_dump(curl_exec($this->ch), curl_errno($this->ch) === CURLE_COULDNT_CONNECT);
        curl_reset($this->ch);
        var_dump(curl_setopt($this->ch, CURLOPT_OPENSOCKETFUNCTION, fn (): bool => false));
        echo "write done\n";
        return true;
    }
}

$ch = curl_init('http://127.0.0.1:1/');
curl_setopt($ch, CURLOPT_PROXY, '');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION, function (): bool {
    echo "callback\n";
    return false;
});

session_set_save_handler(new Handler($ch), false);
unset($ch);
session_id('curlhardening');
session_start();
$_SESSION['x'] = 1;
echo "end of script\n";
?>
--EXPECT--
end of script
callback
bool(false)
bool(true)
bool(true)
write done
