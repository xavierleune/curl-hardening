# curl_hardening

Polyfill of `CURLOPT_OPENSOCKETFUNCTION` as proposed for PHP's `ext/curl` in
PHP 8.7: a callback consulted before every socket libcurl creates, after DNS
resolution and before `connect()`. Its main use is SSRF filtering.

> **Status: 0.x, pre-release.** The API follows the RFC under discussion and
> will change with it.

```php
curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION,
    function (CurlHandle $handle, CurlAddressFamily $family, string $address, ?int $port): bool {
        // Only publicly routable addresses.
        return $family !== CurlAddressFamily::Unix
            && filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE) !== false;
    });
```

`FILTER_FLAG_GLOBAL_RANGE` follows the IANA special-purpose address registries.
For a deny list maintained for outgoing requests, use the one of Symfony's
[`NoPrivateNetworkHttpClient`](https://github.com/symfony/symfony/blob/8.2/src/Symfony/Component/HttpClient/NoPrivateNetworkHttpClient.php),
[`IpUtils::PRIVATE_SUBNETS`](https://github.com/symfony/symfony/blob/8.2/src/Symfony/Component/HttpFoundation/IpUtils.php#L19),
which also refuses the NAT64 prefixes (`64:ff9b::/96` and `64:ff9b:1::/48`):
`FILTER_FLAG_GLOBAL_RANGE` accepts them, while an address such as
`64:ff9b::a9fe:a9fe` reaches 169.254.169.254 through a NAT64 gateway:

```php
use Symfony\Component\HttpFoundation\IpUtils;

return $family !== CurlAddressFamily::Unix
    && !IpUtils::checkIp($address, IpUtils::PRIVATE_SUBNETS);
```

- **`$family`**: `CurlAddressFamily::IpV4`, `IpV6` or `Unix`.
- **`$address`**: a literal IP address, or the socket path for `Unix`.
- **`$port`**: `null` for `Unix`.
- **Return `true`** to allow the connection, **`false`** to refuse it
  (`CURLE_COULDNT_CONNECT`). Any other value raises a `TypeError`, and an
  exception propagates out of `curl_exec()`; both refuse the connection.
- The callback never sees or returns a socket: when it allows the connection,
  the socket is created exactly as libcurl would have created it.
- The option behaves like any other: `null` removes it, `curl_reset()` clears
  it, and `curl_copy_handle()` and `clone` carry it over.

The callback is invoked for each socket libcurl creates:

- A connection reused from the pool of the handle, of its multi handle or of a
  share was vetted when it was opened, if the callback was set then.
  `CURLOPT_PREREQFUNCTION` runs before every request, reused connections
  included.
- With a proxy, the callback is given the proxy's address. Set `CURLOPT_PROXY`
  to `''` to ignore proxies configured in the environment.
- Connections made for `CURLOPT_DOH_URL` are not passed to it.
- Restrict the schemes a transfer may use with `CURLOPT_PROTOCOLS_STR` and
  `CURLOPT_REDIR_PROTOCOLS_STR`, for instance `"http,https"`.

## A polyfill

Everything is only registered when `ext/curl` does not already provide
`CURLOPT_OPENSOCKETFUNCTION`; on a PHP that does, the extension stays inert.
Until then it intercepts `curl_setopt()`, `curl_setopt_array()`, `curl_reset()`,
`curl_copy_handle()` and `curl_close()`, handles the option itself and forwards
everything else to `ext/curl`.

It reaches libcurl through `ext/curl`'s object layout, which is not a public
API. It checks that layout before first use and refuses to set the option,
rather than install a filter that would not be enforced, if it does not match.
That check creates a handle with `curl_init()`, so the option is unavailable
when `curl_init()` is disabled.

Known differences with the native option:

- Handles that `ext/curl` creates for HTTP/2 server push inherit their parent's
  callback, which is invoked with the parent handle. Once the parent is freed,
  their connections are refused.
- `ext/curl` checks after each of its own callbacks that the streams given with
  `CURLOPT_FILE`, `CURLOPT_WRITEHEADER`, `CURLOPT_INFILE` and `CURLOPT_STDERR`
  are still open; the polyfill cannot. Do not close them from the callback.

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
