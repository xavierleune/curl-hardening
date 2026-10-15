/*
 * curl_hardening - connection filtering for PHP's ext/curl
 *
 * Copyright (c) 2026 Xavier Leune
 * SPDX-License-Identifier: MIT
 *
 * See the LICENSE file for the full terms.
 */

#ifndef PHP_CURL_HARDENING_H
#define PHP_CURL_HARDENING_H

#define PHP_CURL_HARDENING_VERSION "0.1.0-dev"

extern zend_module_entry curl_hardening_module_entry;
#define phpext_curl_hardening_ptr &curl_hardening_module_entry

#include "php_version.h"

ZEND_BEGIN_MODULE_GLOBALS(curl_hardening)
	/* CurlHandle object address => its curl_hardening_handle. Request scoped. */
	HashTable handles;
	/* True between RINIT and the point in RSHUTDOWN where bindings are torn
	 * down; ext/curl hooks must not touch the table outside of it. */
	bool active;
	/* 0 = not probed yet, 1 = probe succeeded, -1 = probe failed. */
	int probe_state;
ZEND_END_MODULE_GLOBALS(curl_hardening)

ZEND_EXTERN_MODULE_GLOBALS(curl_hardening)

#define CURL_HARDENING_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(curl_hardening, v)

#endif /* PHP_CURL_HARDENING_H */
