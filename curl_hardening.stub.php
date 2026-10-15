<?php

/**
 * Polyfill of the connection filtering API proposed for ext/curl in PHP 8.7.
 * Everything below is only registered when ext/curl does not already provide it.
 *
 * @generate-class-entries
 */

/**
 * @var int
 * @cvalue CURLOPT_OPENSOCKETFUNCTION
 */
const CURLOPT_OPENSOCKETFUNCTION = UNKNOWN;
/**
 * @var int
 * @cvalue CURLSOCKTYPE_IPCXN
 */
const CURLSOCKTYPE_IPCXN = UNKNOWN;

enum CurlAddressFamily
{
    case IpV4;
    case IpV6;
    case Unix;
}

/**
 * The endpoint libcurl is about to connect to, passed to the
 * CURLOPT_OPENSOCKETFUNCTION callback. Only ext/curl creates instances.
 *
 * @strict-properties
 * @not-serializable
 */
final readonly class CurlSocketAddress
{
    public CurlAddressFamily $family;

    /** A literal IP address, or the socket path for CurlAddressFamily::Unix. */
    public string $address;

    /** 0 for CurlAddressFamily::Unix. */
    public int $port;

    private function __construct() {}
}

/**
 * Describes the socket to create for a connection the callback allows. It never
 * holds a descriptor: ext/curl creates the socket once the callback returns.
 *
 * @strict-properties
 * @not-serializable
 */
final class CurlSocket
{
    /** Binds the local end of the connection to $address and $port. */
    public function bind(string $address, int $port = 0): void {}
}
