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
 * The address family of the endpoint libcurl is about to connect to, as reported
 * to the CURLOPT_OPENSOCKETFUNCTION callback.
 */
enum CurlAddressFamily
{
    case IpV4;
    case IpV6;
    case Unix;
}
