# curl_hardening

Polyfill of `CURLOPT_OPENSOCKETFUNCTION` as proposed for PHP's `ext/curl` in
PHP 8.7: a callback consulted before every socket libcurl creates, after DNS
resolution and before `connect()`. Its main use is SSRF filtering.

> **Status: 0.x, pre-release.** The API follows the RFC under discussion and
> will change with it.

```php
curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION,
    function (CurlHandle $handle, int $purpose, CurlSocketAddress $address): ?CurlSocket {
        if ($address->family === CurlAddressFamily::Unix) {
            return null;
        }
        if (filter_var($address->address, FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return null;                       // loopback, private, reserved
        }
        return new CurlSocket();
    });
```

- **`CurlSocketAddress`** — `$family` (`CurlAddressFamily::IpV4`, `IpV6`,
  `Unix`), `$address` (a literal IP, or the socket path), `$port` (0 for Unix).
- **Return a `CurlSocket`** to allow the connection, **`null`** to refuse it
  (`CURLE_COULDNT_CONNECT`). Any other value raises a `TypeError`; an exception
  propagates out of `curl_exec()`. Both refuse.
- **`CurlSocket`** describes the socket to create and never holds a descriptor.
  `bind()` picks the local address per destination; it cannot be combined with
  `CURLOPT_INTERFACE` or `CURLOPT_LOCALPORT` on the same handle.
- The option behaves like any other: `null` removes it, `curl_reset()` clears
  it, `curl_copy_handle()` and `clone` carry it over.

It is not on its own a complete SSRF defence: schemes that open no socket
(`file://`) bypass it, as do connections made for `CURLOPT_DOH_URL`; with a proxy
it sees the proxy, not the target; a reused pooled connection is not seen again.
Restrict schemes with `CURLOPT_PROTOCOLS_STR` and `CURLOPT_REDIR_PROTOCOLS_STR`,
and set `CURLOPT_PROXY` to `''` to ignore proxies from the environment.

## A polyfill

Everything is only registered when `ext/curl` does not already provide
`CURLOPT_OPENSOCKETFUNCTION`; on a PHP that does, the extension stays inert.
Until then it intercepts `curl_setopt()`, `curl_setopt_array()`, `curl_reset()`
and `curl_copy_handle()`, handles the option itself and forwards everything else
to `ext/curl` untouched, with the same error messages.

It reaches libcurl through `ext/curl`'s object layout, which is not a public
API. It checks that layout before first use and refuses to set the option,
rather than install a filter that would not be enforced, if it does not match.

## Building

```sh
phpize
./configure --enable-curl-hardening
make
make test
```

Requires PHP 8.3 or later, `ext/curl` and libcurl ≥ 7.61. POSIX only for now.

## License

MIT — see [LICENSE](LICENSE).
