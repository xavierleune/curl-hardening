/*
 * curl_hardening - connection filtering for PHP's ext/curl
 *
 * Copyright (c) 2026 Xavier Leune
 * SPDX-License-Identifier: MIT
 *
 * See the LICENSE file for the full terms.
 */

/*
 * Polyfill of CURLOPT_OPENSOCKETFUNCTION as proposed for ext/curl in PHP 8.7:
 *
 *     curl_setopt($ch, CURLOPT_OPENSOCKETFUNCTION,
 *         function (CurlHandle $handle, CurlAddressFamily $family, string $address, ?int $port): bool { ... });
 *
 * ext/curl does not know about the option, so the extension intercepts the
 * ext/curl functions and handlers that need to (see "Interception of ext/curl")
 * and forwards everything else untouched. When ext/curl already provides the
 * option, the extension registers nothing and intercepts nothing.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "Zend/zend_exceptions.h"
#include "Zend/zend_enum.h"
#include "ext/standard/info.h"
#include "ext/standard/php_net.h"
#include "ext/curl/php_curl.h"
#include "php_network.h"

#include <stddef.h>
#include <string.h>

#ifdef PHP_WIN32
# include <winsock2.h>
# include <ws2tcpip.h>
#else
# include <sys/socket.h>
# include <sys/un.h>
# include <netinet/in.h>
# include <arpa/inet.h>
#endif

#include <curl/curl.h>

#include "php_curl_hardening.h"
#include "curl_hardening_arginfo.h"

#if PHP_VERSION_ID < 80300
# error "curl_hardening currently requires PHP 8.3 or later"
#endif

ZEND_DECLARE_MODULE_GLOBALS(curl_hardening)

/* True once MINIT registered the polyfill; false when ext/curl is native. */
static bool curl_hardening_enabled;

static zend_class_entry *curl_address_family_ce;

/* {{{ Reaching libcurl through ext/curl
 *
 * ext/curl installs only php_curl.h, which exposes nothing but class entries:
 * no php_curl definition, no accessor for the underlying CURL *. Copying the
 * struct is not an option either: php_curl embeds php_curl_handlers by value,
 * and that struct has members conditional on LIBCURL_VERSION_NUM, so
 * offsetof(php_curl, std) depends on the libcurl PHP itself was built against,
 * which this extension cannot know at its own compile time.
 *
 * The offset is however carried at runtime by the object's handler table, where
 * ext/curl set it to offsetof(php_curl, std). Reading it there leaves two
 * assumptions, both checked by curl_hardening_probe():
 *
 *   1. zend_object.handlers->offset is readable (public API, stable on 8.x);
 *   2. CURL *cp is the first member of php_curl (verified on PHP 8.2 to 8.6).
 */
static CURL *curl_hardening_easy_handle(zend_object *obj)
{
	if (UNEXPECTED(obj->ce != curl_ce || obj->handlers == NULL)) {
		return NULL;
	}

	return *(CURL **) ((char *) obj - obj->handlers->offset);
}

/* Round-trips an option through the derived pointer, on a real handle built by
 * curl_init() -- object_init_ex() alone would leave cp NULL. Once per request. */
static bool curl_hardening_probe(void)
{
	if (CURL_HARDENING_G(probe_state) != 0) {
		return CURL_HARDENING_G(probe_state) > 0;
	}

	/* A filter that is silently absent is worse than one that refuses to
	 * install: assume failure until proven otherwise. */
	CURL_HARDENING_G(probe_state) = -1;

	/* Calling a function is a no-op while an exception is pending, which
	 * curl_setopt_array() may reach us with: set it aside for the probe. We
	 * run inside an internal function, so no opline needs saving with it. */
	zend_object *pending = EG(exception);
	EG(exception) = NULL;

	zval fname, handle;
	ZVAL_STRING(&fname, "curl_init");
	ZVAL_UNDEF(&handle);

	if (call_user_function(NULL, NULL, &fname, &handle, 0, NULL) == SUCCESS
			&& Z_TYPE(handle) == IS_OBJECT && Z_OBJCE(handle) == curl_ce) {
		CURL *cp = curl_hardening_easy_handle(Z_OBJ(handle));
		static const char probe_url[] = "http://127.0.0.1:1/curl-hardening-probe";
		char *effective = NULL;

		if (cp != NULL
				&& curl_easy_setopt(cp, CURLOPT_URL, probe_url) == CURLE_OK
				&& curl_easy_getinfo(cp, CURLINFO_EFFECTIVE_URL, &effective) == CURLE_OK
				&& effective != NULL
				&& strcmp(effective, probe_url) == 0) {
			CURL_HARDENING_G(probe_state) = 1;
		}
	}

	zval_ptr_dtor(&fname);
	zval_ptr_dtor(&handle);

	if (pending != NULL) {
		if (EG(exception) != NULL) {
			zend_exception_set_previous(EG(exception), pending);
		} else {
			EG(exception) = pending;
		}
	}

	return CURL_HARDENING_G(probe_state) > 0;
}
/* }}} */

/* {{{ Per-handle state
 *
 * ext/curl gives us nowhere to store anything on a CurlHandle, so every handle
 * the extension deals with gets a curl_hardening_handle, kept in a
 * request-scoped table keyed by object address and freed together with the
 * object. Its id, unique for the life of the process, is what libcurl's
 * CURLOPT_OPENSOCKETDATA holds, which is how the callback finds the handle
 * performing the transfer.
 *
 * The callback itself lives in a curl_hardening_state, shared by a handle and
 * its copies and reference counted, one reference per handle. States are
 * immutable: setting the option always creates a new one, so a copy keeps the
 * callback it was copied with, as it does for every other option.
 *
 * Each of those references also holds its own reference to the callback's
 * object and closure. The callback is reported to the cycle collector from
 * every bound handle, and the collector needs one real reference behind every
 * reported edge.
 */
typedef struct {
	zend_fcall_info_cache fcc;
	uint32_t refcount;
} curl_hardening_state;

typedef struct {
	zend_object *object;          /* not a counted reference: freed with it */
	curl_hardening_state *state;  /* one counted reference, or NULL */
	zend_ulong id;
	bool in_callback;
} curl_hardening_handle;

#define CURL_HARDENING_KEY(obj) ((zend_ulong) (uintptr_t) (obj))

static void curl_hardening_state_acquire(curl_hardening_state *state)
{
	if (state->fcc.object != NULL) {
		GC_ADDREF(state->fcc.object);
	}
	if (state->fcc.closure != NULL) {
		GC_ADDREF(state->fcc.closure);
	}
	state->refcount++;
}

static void curl_hardening_state_release(curl_hardening_state *state)
{
	if (state == NULL) {
		return;
	}

	if (--state->refcount == 0) {
		/* Drops the last references, and a copied trampoline if any. */
		zend_fcc_dtor(&state->fcc);
		efree(state);
		return;
	}

	if (state->fcc.object != NULL) {
		OBJ_RELEASE(state->fcc.object);
	}
	if (state->fcc.closure != NULL) {
		OBJ_RELEASE(state->fcc.closure);
	}
}

/* Both lookups find nothing outside a request: the tables do not exist then. */
static curl_hardening_handle *curl_hardening_handle_find(zend_object *obj)
{
	if (!CURL_HARDENING_G(active)) {
		return NULL;
	}

	return zend_hash_index_find_ptr(&CURL_HARDENING_G(handles), CURL_HARDENING_KEY(obj));
}

static curl_hardening_handle *curl_hardening_handle_find_id(zend_ulong id)
{
	if (!CURL_HARDENING_G(active)) {
		return NULL;
	}

	return zend_hash_index_find_ptr(&CURL_HARDENING_G(ids), id);
}

/* Only called while active. */
static curl_hardening_handle *curl_hardening_handle_get(zend_object *obj)
{
	curl_hardening_handle *hh = curl_hardening_handle_find(obj);

	if (hh == NULL) {
		hh = ecalloc(1, sizeof(curl_hardening_handle));
		hh->object = obj;
		hh->id = ++CURL_HARDENING_G(last_id);
		zend_hash_index_add_new_ptr(&CURL_HARDENING_G(handles), CURL_HARDENING_KEY(obj), hh);
		zend_hash_index_add_new_ptr(&CURL_HARDENING_G(ids), hh->id, hh);
	}

	return hh;
}

static void curl_hardening_handle_free(curl_hardening_handle *hh)
{
	curl_hardening_state_release(hh->state);
	efree(hh);
}

static curl_socket_t curl_hardening_opensocket(void *clientp, curlsocktype purpose,
		struct curl_sockaddr *address);

/* libcurl's option is armed if and only if hh->state is set.
 *
 * libcurl copies CURLOPT_OPENSOCKETDATA into easy handles we never see: those
 * ext/curl creates for HTTP/2 server push duplicate their parent's options
 * without going through curl_copy_handle() or clone. A pointer could then
 * outlive the handle it designates. An id cannot: the trampoline looks it up,
 * and refuses the connection once its handle is gone. */
static void curl_hardening_arm(curl_hardening_handle *hh)
{
	CURL *cp = curl_hardening_easy_handle(hh->object);

	if (cp != NULL) {
		curl_easy_setopt(cp, CURLOPT_OPENSOCKETFUNCTION, curl_hardening_opensocket);
		curl_easy_setopt(cp, CURLOPT_OPENSOCKETDATA, (void *) (uintptr_t) hh->id);
	}
}

static void curl_hardening_disarm(zend_object *obj)
{
	CURL *cp = curl_hardening_easy_handle(obj);

	if (cp != NULL) {
		curl_easy_setopt(cp, CURLOPT_OPENSOCKETFUNCTION, NULL);
		curl_easy_setopt(cp, CURLOPT_OPENSOCKETDATA, NULL);
	}
}
/* }}} */

/* {{{ Describing the endpoint */
#if defined(AF_UNIX) && !defined(PHP_WIN32)
/* The path of a UNIX domain socket, as libcurl built it. A Linux abstract
 * socket name starts with a NUL byte, which is kept: it is part of the name. */
static zend_string *curl_hardening_unix_path(const struct curl_sockaddr *address)
{
	const struct sockaddr_un *sun = (const struct sockaddr_un *) &address->addr;
	size_t offset = offsetof(struct sockaddr_un, sun_path);
	size_t len = address->addrlen > offset ? address->addrlen - offset : 0;

	if (len > sizeof(sun->sun_path)) {
		len = sizeof(sun->sun_path);
	}
	if (len > 0 && sun->sun_path[0] != '\0') {
		/* A pathname: libcurl may count the terminating NUL in addrlen. */
		len = zend_strnlen(sun->sun_path, len);
	}

	return zend_string_init(sun->sun_path, len, 0);
}
#endif

/* Fills the $family, $address and $port arguments. Returns false for anything
 * that cannot be described, which is then refused without calling the callback. */
static bool curl_hardening_describe(zval *args, const struct curl_sockaddr *address)
{
	const char *family;

	switch (address->family) {
		case AF_INET:
			family = "IpV4";
			ZVAL_LONG(&args[2], ntohs(((const struct sockaddr_in *) &address->addr)->sin_port));
			break;
#ifdef AF_INET6
		case AF_INET6:
			family = "IpV6";
			ZVAL_LONG(&args[2], ntohs(((const struct sockaddr_in6 *) &address->addr)->sin6_port));
			break;
#endif
#if defined(AF_UNIX) && !defined(PHP_WIN32)
		case AF_UNIX:
			/* A path has no port. */
			family = "Unix";
			ZVAL_NULL(&args[2]);
			break;
#endif
		default:
			return false;
	}

#if defined(AF_UNIX) && !defined(PHP_WIN32)
	if (address->family == AF_UNIX) {
		ZVAL_STR(&args[1], curl_hardening_unix_path(address));
	} else
#endif
	{
		zend_string *ip = php_inet_ntop(&address->addr);
		if (ip == NULL) {
			return false;
		}
		ZVAL_STR(&args[1], ip);
	}

	ZVAL_OBJ_COPY(&args[0], zend_enum_get_case_cstr(curl_address_family_ce, family));
	return true;
}
/* }}} */

/* {{{ The CURLOPT_OPENSOCKETFUNCTION trampoline */
static curl_socket_t curl_hardening_opensocket(void *clientp, curlsocktype purpose,
		struct curl_sockaddr *address)
{
	curl_hardening_handle *hh = curl_hardening_handle_find_id((zend_ulong) (uintptr_t) clientp);
	curl_hardening_state *state = hh != NULL ? hh->state : NULL;

	/* Whatever cannot be described to the callback is refused without calling
	 * it: a policy must never be bypassed by an endpoint it was not shown.
	 * CURLSOCKTYPE_IPCXN is the only purpose libcurl currently uses; a future
	 * one may well not designate a destination at all. An unknown id is a
	 * handle that is gone (see curl_hardening_arm()). */
	if (UNEXPECTED(state == NULL || purpose != CURLSOCKTYPE_IPCXN)) {
		return CURL_SOCKET_BAD;
	}

	zval args[4], retval;

	if (!curl_hardening_describe(&args[1], address)) {
		return CURL_SOCKET_BAD;
	}

	/* The callback may replace or remove itself: keep this state alive. The
	 * handle is kept alive by the reference passed to the callback, and so is
	 * hh, which is only freed with its object. */
	curl_hardening_state_acquire(state);
	GC_ADDREF(hh->object);
	ZVAL_OBJ(&args[0], hh->object);
	ZVAL_UNDEF(&retval);

	bool was_in_callback = hh->in_callback;
	hh->in_callback = true;
	zend_call_known_fcc(&state->fcc, &retval, /* param_count */ 4, args, /* named_params */ NULL);
	hh->in_callback = was_in_callback;

	curl_socket_t fd = CURL_SOCKET_BAD;

	/* retval is undefined when the callback threw: the connection is refused
	 * and the exception propagates out of curl_exec(). */
	if (!Z_ISUNDEF(retval)) {
		if (Z_TYPE(retval) == IS_TRUE) {
			/* What libcurl documents as the default behaviour of the hook. */
			fd = socket(address->family, address->socktype, address->protocol);
			/* Where socket() supports SOCK_NONBLOCK, libcurl only makes a socket
			 * non-blocking if it came from this callback, which it checks after
			 * the call: if the callback removed the option, the socket would
			 * stay blocking and ignore the connect timeout. */
			if (fd != CURL_SOCKET_BAD && php_set_sock_blocking(fd, false) != SUCCESS) {
				closesocket(fd);
				fd = CURL_SOCKET_BAD;
			}
		} else if (Z_TYPE(retval) != IS_FALSE) {
			zend_type_error("The CURLOPT_OPENSOCKETFUNCTION callback must return a bool");
		}
		zval_ptr_dtor(&retval);
	}

	zval_ptr_dtor(&args[0]);
	zval_ptr_dtor(&args[1]);
	zval_ptr_dtor(&args[2]);
	curl_hardening_state_release(state);

	return fd;
}
/* }}} */


/* {{{ Setting the option
 *
 * Mirrors ext/curl's handling of its callable options: the previous callback is
 * released first, so a rejected callable leaves the option unset, and null
 * removes it. is_array_config selects the argument curl_setopt_array() blames.
 */
static bool curl_hardening_set_callback(zend_object *obj, zval *value, bool is_array_config)
{
	ZVAL_DEREF(value);

	if (!CURL_HARDENING_G(active) || !curl_hardening_probe()) {
		zend_throw_error(NULL,
			"CURLOPT_OPENSOCKETFUNCTION is unavailable: curl_hardening cannot reach libcurl "
			"through this ext/curl build, and refuses to install a filter that would not be enforced");
		return false;
	}

	curl_hardening_handle *hh = curl_hardening_handle_get(obj);
	curl_hardening_state *previous = hh->state;
	bool ok = true;

	hh->state = NULL;
	curl_hardening_disarm(obj);

	if (Z_TYPE_P(value) != IS_NULL) {
		zend_fcall_info_cache fcc;
		char *error = NULL;

		if (!zend_is_callable_ex(value, /* object */ NULL, /* check_flags */ 0, /* callable_name */ NULL, &fcc, &error)) {
			if (!EG(exception)) {
				zend_argument_type_error(2 + !is_array_config,
					"must be a valid callback for option CURLOPT_OPENSOCKETFUNCTION, %s", error);
			}
			ok = false;
		} else {
			curl_hardening_state *state = emalloc(sizeof(curl_hardening_state));
			state->fcc = fcc;
			state->refcount = 1;
			zend_fcc_addref(&state->fcc);
			hh->state = state;
			curl_hardening_arm(hh);
		}

		if (error != NULL) {
			efree(error);
		}
	}

	/* Last, once the table and libcurl agree: releasing a callback may free
	 * objects, CurlHandles included, and re-enter curl_hardening_free_obj(). */
	curl_hardening_state_release(previous);

	return ok;
}

/* }}} */

/* {{{ Interception of ext/curl
 *
 * Installed at MINIT, removed at MSHUTDOWN, only when ext/curl does not already
 * provide the option. Each hook calls through to ext/curl for anything that is
 * not ours:
 *
 * - curl_setopt(), curl_setopt_array(): set CURLOPT_OPENSOCKETFUNCTION;
 * - curl_reset(): drop the callback like any other option, and refuse to run
 *   from within it, as ext/curl does for its own callbacks -- libcurl's
 *   curl_easy_reset() performs no such check;
 * - curl_close(): refuse to run from within the callback, as ext/curl does;
 * - CurlHandle's clone_obj handler: `clone $handle` on every version, and
 *   curl_copy_handle() from PHP 8.5 on, which routes through it;
 * - curl_copy_handle() itself: before PHP 8.5 it duplicates the handle directly
 *   and never reaches clone_obj. From 8.5 a copy reaches both hooks; copying the
 *   state is idempotent;
 * - CurlHandle's free_obj handler: releases a handle's state after libcurl let
 *   go of it;
 * - CurlHandle's get_gc handler: reports the callback, so that a callback
 *   capturing its own handle forms a cycle the collector can see.
 */
static zend_object_handlers *curl_hardening_curl_handlers;
static zend_object *(*curl_hardening_orig_clone_obj)(zend_object *object);
static void (*curl_hardening_orig_free_obj)(zend_object *object);
static HashTable *(*curl_hardening_orig_get_gc)(zend_object *object, zval **table, int *n);

typedef struct {
	const char *name;
	size_t name_len;
	zif_handler hook;
	zif_handler original;
} curl_hardening_function_hook;

static ZEND_NAMED_FUNCTION(curl_hardening_setopt);
static ZEND_NAMED_FUNCTION(curl_hardening_setopt_array);
static ZEND_NAMED_FUNCTION(curl_hardening_reset);
static ZEND_NAMED_FUNCTION(curl_hardening_copy_handle);
static ZEND_NAMED_FUNCTION(curl_hardening_close);

enum { HOOK_SETOPT, HOOK_SETOPT_ARRAY, HOOK_RESET, HOOK_COPY_HANDLE, HOOK_CLOSE, HOOK_COUNT };

static curl_hardening_function_hook curl_hardening_hooks[HOOK_COUNT] = {
	[HOOK_SETOPT]       = { "curl_setopt",       sizeof("curl_setopt") - 1,       curl_hardening_setopt,       NULL },
	[HOOK_SETOPT_ARRAY] = { "curl_setopt_array", sizeof("curl_setopt_array") - 1, curl_hardening_setopt_array, NULL },
	[HOOK_RESET]        = { "curl_reset",        sizeof("curl_reset") - 1,        curl_hardening_reset,        NULL },
	[HOOK_COPY_HANDLE]  = { "curl_copy_handle",  sizeof("curl_copy_handle") - 1,  curl_hardening_copy_handle,  NULL },
	[HOOK_CLOSE]        = { "curl_close",        sizeof("curl_close") - 1,        curl_hardening_close,        NULL },
};

#define CURL_HARDENING_CALL_ORIGINAL(hook) \
	curl_hardening_hooks[hook].original(INTERNAL_FUNCTION_PARAM_PASSTHRU)

/* Whether the option argument designates CURLOPT_OPENSOCKETFUNCTION, recognised
 * without parsing the arguments ourselves, which would repeat any diagnostic
 * ext/curl emits for the calls we merely forward. Besides an int, a numeric
 * string is accepted in coercive typing mode, as ext/curl's int parameter would
 * accept it, so that both reach the same option. */
static bool curl_hardening_arg_is_ours(zend_execute_data *execute_data, uint32_t num)
{
	if (ZEND_NUM_ARGS() < num) {
		return false;
	}

	zval *arg = ZEND_CALL_ARG(execute_data, num);
	ZVAL_DEREF(arg);

	if (Z_TYPE_P(arg) == IS_LONG) {
		return Z_LVAL_P(arg) == CURLOPT_OPENSOCKETFUNCTION;
	}

	zend_long lval;
	return Z_TYPE_P(arg) == IS_STRING
		&& !ZEND_ARG_USES_STRICT_TYPES()
		&& is_numeric_string(Z_STRVAL_P(arg), Z_STRLEN_P(arg), &lval, NULL, false) == IS_LONG
		&& lval == CURLOPT_OPENSOCKETFUNCTION;
}

static ZEND_NAMED_FUNCTION(curl_hardening_setopt)
{
	if (!curl_hardening_arg_is_ours(execute_data, 2)) {
		CURL_HARDENING_CALL_ORIGINAL(HOOK_SETOPT);
		return;
	}

	zval *zid, *zvalue;
	zend_long option;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_OBJECT_OF_CLASS(zid, curl_ce)
		Z_PARAM_LONG(option)
		Z_PARAM_ZVAL(zvalue)
	ZEND_PARSE_PARAMETERS_END();

	RETURN_BOOL(curl_hardening_set_callback(Z_OBJ_P(zid), zvalue, /* is_array_config */ false));
}

/* Applies a run of options that are not ours through ext/curl, by calling its
 * handler on the current frame with the array argument swapped for the run.
 * Going through zend_call_function() instead would differ from a native call:
 * it adds a frame to traces, discards the result when an exception is pending,
 * and does not call anything at all if one already is -- an error handler
 * turning a notice into an exception would then stop the remaining options,
 * where ext/curl applies them. Like ext/curl, stop only on a false result.
 *
 * The run is a counted reference: an exception thrown by ext/curl captures it
 * in its trace, so the caller must release it, never clear it in place. */
static bool curl_hardening_apply_segment(zend_execute_data *execute_data, zval *segment)
{
	if (zend_hash_num_elements(Z_ARRVAL_P(segment)) == 0) {
		return true;
	}

	zval *arg = ZEND_CALL_ARG(execute_data, 2);
	zval saved, retval;

	ZVAL_COPY_VALUE(&saved, arg);
	ZVAL_COPY_VALUE(arg, segment);
	ZVAL_NULL(&retval);

	curl_hardening_hooks[HOOK_SETOPT_ARRAY].original(execute_data, &retval);

	ZVAL_COPY_VALUE(arg, &saved);

	bool ok = Z_TYPE(retval) == IS_TRUE;
	zval_ptr_dtor(&retval);

	return ok;
}

static ZEND_NAMED_FUNCTION(curl_hardening_setopt_array)
{
	zval *arr = ZEND_NUM_ARGS() >= 2 ? ZEND_CALL_ARG(execute_data, 2) : NULL;

	if (arr != NULL) {
		ZVAL_DEREF(arr);
	}

	/* The common case: the option is not in the array, ext/curl does it all. */
	if (arr == NULL || Z_TYPE_P(arr) != IS_ARRAY
			|| !zend_hash_index_exists(Z_ARRVAL_P(arr), CURLOPT_OPENSOCKETFUNCTION)) {
		CURL_HARDENING_CALL_ORIGINAL(HOOK_SETOPT_ARRAY);
		return;
	}

	zval *zid;
	HashTable *options;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_OBJECT_OF_CLASS(zid, curl_ce)
		Z_PARAM_ARRAY_HT(options)
	ZEND_PARSE_PARAMETERS_END();

	/* Apply in order, like ext/curl: the options before ours, ours, then the
	 * rest -- stopping at the first failure. */
	zval segment;
	zend_ulong option;
	zend_string *key;
	zval *value;
	bool ok = true;

	array_init(&segment);

	ZEND_HASH_FOREACH_KEY_VAL(options, option, key, value) {
		if (key == NULL && option == CURLOPT_OPENSOCKETFUNCTION) {
			ok = curl_hardening_apply_segment(execute_data, &segment)
				&& curl_hardening_set_callback(Z_OBJ_P(zid), value, /* is_array_config */ true);
			zval_ptr_dtor(&segment);
			array_init(&segment);
			if (!ok) {
				break;
			}
			continue;
		}

		Z_TRY_ADDREF_P(value);
		if (key != NULL) {
			zend_hash_update(Z_ARRVAL(segment), key, value);
		} else {
			zend_hash_index_update(Z_ARRVAL(segment), option, value);
		}
	} ZEND_HASH_FOREACH_END();

	if (ok) {
		ok = curl_hardening_apply_segment(execute_data, &segment);
	}

	zval_ptr_dtor(&segment);
	RETURN_BOOL(ok);
}

static ZEND_NAMED_FUNCTION(curl_hardening_reset)
{
	zval *zid;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_OBJECT_OF_CLASS(zid, curl_ce)
	ZEND_PARSE_PARAMETERS_END();

	curl_hardening_handle *hh = curl_hardening_handle_find(Z_OBJ_P(zid));

	if (hh != NULL && hh->in_callback) {
		zend_throw_error(NULL, "%s(): Attempt to reset cURL handle from a callback", get_active_function_name());
		RETURN_THROWS();
	}

	CURL_HARDENING_CALL_ORIGINAL(HOOK_RESET);

	if (hh != NULL && !EG(exception)) {
		/* curl_easy_reset() cleared libcurl's side: release ours. */
		curl_hardening_state *state = hh->state;
		hh->state = NULL;
		curl_hardening_state_release(state);
	}
}

static ZEND_NAMED_FUNCTION(curl_hardening_close)
{
	zval *handle = ZEND_NUM_ARGS() >= 1 ? ZEND_CALL_ARG(execute_data, 1) : NULL;

	if (handle != NULL) {
		ZVAL_DEREF(handle);
		if (Z_TYPE_P(handle) == IS_OBJECT && Z_OBJCE_P(handle) == curl_ce) {
			curl_hardening_handle *hh = curl_hardening_handle_find(Z_OBJ_P(handle));
			if (hh != NULL && hh->in_callback) {
				zend_throw_error(NULL, "%s(): Attempt to close cURL handle from a callback", get_active_function_name());
				RETURN_THROWS();
			}
		}
	}

	CURL_HARDENING_CALL_ORIGINAL(HOOK_CLOSE);
}

/* dst is a copy of src: it gets src's options, ours included, and its own
 * CURLOPT_OPENSOCKETDATA -- libcurl copied src's. */
static void curl_hardening_bind_copy(zend_object *src, zend_object *dst)
{
	if (!CURL_HARDENING_G(active)) {
		return;
	}

	curl_hardening_handle *from = curl_hardening_handle_find(src);
	if (from == NULL || curl_hardening_handle_find(dst) != NULL) {
		return;
	}

	if (from->state != NULL) {
		curl_hardening_handle *to = curl_hardening_handle_get(dst);
		to->state = from->state;
		curl_hardening_state_acquire(to->state);
		curl_hardening_arm(to);
	}
}

static ZEND_NAMED_FUNCTION(curl_hardening_copy_handle)
{
	zval *source = ZEND_NUM_ARGS() >= 1 ? ZEND_CALL_ARG(execute_data, 1) : NULL;

	CURL_HARDENING_CALL_ORIGINAL(HOOK_COPY_HANDLE);

	if (source != NULL) {
		ZVAL_DEREF(source);
		if (Z_TYPE_P(source) == IS_OBJECT && Z_TYPE_P(return_value) == IS_OBJECT) {
			curl_hardening_bind_copy(Z_OBJ_P(source), Z_OBJ_P(return_value));
		}
	}
}

static zend_object *curl_hardening_clone_obj(zend_object *object)
{
	zend_object *clone = curl_hardening_orig_clone_obj(object);

	if (clone != NULL) {
		curl_hardening_bind_copy(object, clone);
	}

	return clone;
}

static void curl_hardening_free_obj(zend_object *object)
{
	curl_hardening_handle *hh = curl_hardening_handle_find(object);

	if (hh != NULL) {
		/* From here on, the trampoline refuses whatever still carries the id. */
		zend_hash_index_del(&CURL_HARDENING_G(handles), CURL_HARDENING_KEY(object));
		zend_hash_index_del(&CURL_HARDENING_G(ids), hh->id);
	}

	curl_hardening_orig_free_obj(object);

	if (hh != NULL) {
		curl_hardening_handle_free(hh);
	}
}

static HashTable *curl_hardening_get_gc(zend_object *object, zval **table, int *n)
{
	HashTable *properties = curl_hardening_orig_get_gc(object, table, n);

	if (!CURL_HARDENING_G(active)) {
		return properties;
	}

	curl_hardening_handle *hh = curl_hardening_handle_find(object);
	zend_get_gc_buffer *buffer = &EG(get_gc_buffer);

	/* ext/curl reports through the shared buffer: append to it and republish.
	 * Should it ever report otherwise, stay out of the way rather than clobber
	 * its table. */
	if (hh != NULL && hh->state != NULL && *table == buffer->start) {
		zend_get_gc_buffer_add_fcc(buffer, &hh->state->fcc);
		zend_get_gc_buffer_use(buffer, table, n);
	}

	return properties;
}

static zend_result curl_hardening_hook_curl(void)
{
	/* ext/curl's curl_object_handlers, shared by every CurlHandle, clones
	 * included. It is a plain static, only exposed as const. */
	zend_object_handlers *handlers = (zend_object_handlers *) curl_ce->default_object_handlers;

	if (handlers == NULL || handlers->clone_obj == NULL || handlers->free_obj == NULL
			|| handlers->get_gc == NULL) {
		return FAILURE;
	}

	zend_function *functions[HOOK_COUNT];

	for (int i = 0; i < HOOK_COUNT; i++) {
		functions[i] = zend_hash_str_find_ptr(CG(function_table),
			curl_hardening_hooks[i].name, curl_hardening_hooks[i].name_len);
		if (functions[i] == NULL || functions[i]->type != ZEND_INTERNAL_FUNCTION) {
			return FAILURE;
		}
	}

	for (int i = 0; i < HOOK_COUNT; i++) {
		curl_hardening_hooks[i].original = functions[i]->internal_function.handler;
		functions[i]->internal_function.handler = curl_hardening_hooks[i].hook;
	}

	curl_hardening_curl_handlers = handlers;
	curl_hardening_orig_clone_obj = handlers->clone_obj;
	curl_hardening_orig_free_obj = handlers->free_obj;
	curl_hardening_orig_get_gc = handlers->get_gc;
	handlers->clone_obj = curl_hardening_clone_obj;
	handlers->free_obj = curl_hardening_free_obj;
	handlers->get_gc = curl_hardening_get_gc;

	return SUCCESS;
}

static void curl_hardening_unhook_curl(void)
{
	/* Looked up again rather than kept from MINIT: disable_functions removes
	 * functions from the table, and frees them, after every MINIT ran. */
	for (int i = 0; i < HOOK_COUNT; i++) {
		zend_function *fn = zend_hash_str_find_ptr(CG(function_table),
			curl_hardening_hooks[i].name, curl_hardening_hooks[i].name_len);
		if (fn != NULL && fn->type == ZEND_INTERNAL_FUNCTION
				&& fn->internal_function.handler == curl_hardening_hooks[i].hook) {
			fn->internal_function.handler = curl_hardening_hooks[i].original;
		}
	}

	if (curl_hardening_curl_handlers != NULL) {
		curl_hardening_curl_handlers->clone_obj = curl_hardening_orig_clone_obj;
		curl_hardening_curl_handlers->free_obj = curl_hardening_orig_free_obj;
		curl_hardening_curl_handlers->get_gc = curl_hardening_orig_get_gc;
		curl_hardening_curl_handlers = NULL;
	}
}
/* }}} */

/* {{{ Module lifecycle */
static PHP_GINIT_FUNCTION(curl_hardening)
{
#if defined(COMPILE_DL_CURL_HARDENING) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	curl_hardening_globals->probe_state = 0;
	curl_hardening_globals->active = false;
	curl_hardening_globals->last_id = 0;
}

static PHP_RINIT_FUNCTION(curl_hardening)
{
#if defined(COMPILE_DL_CURL_HARDENING) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif
	if (!curl_hardening_enabled) {
		return SUCCESS;
	}

	CURL_HARDENING_G(probe_state) = 0;
	/* Request scoped: their buckets come from the request heap. */
	zend_hash_init(&CURL_HARDENING_G(handles), 8, NULL, NULL, 0);
	zend_hash_init(&CURL_HARDENING_G(ids), 8, NULL, NULL, 0);
	CURL_HARDENING_G(active) = true;

	return SUCCESS;
}

/* No RSHUTDOWN: user code still runs after it, from the RSHUTDOWN of extensions
 * that come later (session handlers writing the session, for instance), and
 * must find its callbacks in place. The tables are torn down once the executor
 * freed every object, each CurlHandle releasing its own binding on the way. */
static ZEND_MODULE_POST_ZEND_DEACTIVATE_D(curl_hardening)
{
	if (!CURL_HARDENING_G(active)) {
		return SUCCESS;
	}

	CURL_HARDENING_G(active) = false;

	/* Whatever is left belongs to objects that were never freed, after a fatal
	 * error for instance. Those objects, and the callbacks' objects, may be gone
	 * already: free our own memory without touching them. */
	curl_hardening_handle *hh;
	ZEND_HASH_FOREACH_PTR(&CURL_HARDENING_G(handles), hh) {
		if (hh->state != NULL && --hh->state->refcount == 0) {
			efree(hh->state);
		}
		efree(hh);
	} ZEND_HASH_FOREACH_END();

	zend_hash_destroy(&CURL_HARDENING_G(ids));
	zend_hash_destroy(&CURL_HARDENING_G(handles));

	return SUCCESS;
}

static PHP_MINFO_FUNCTION(curl_hardening)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "curl_hardening support", "enabled");
	php_info_print_table_row(2, "Version", PHP_CURL_HARDENING_VERSION);
	php_info_print_table_row(2, "CURLOPT_OPENSOCKETFUNCTION",
		!curl_hardening_enabled ? "provided natively by ext/curl, polyfill inactive"
			: (curl_hardening_probe() ? "polyfilled" : "unavailable: ext/curl layout not recognised"));
	php_info_print_table_end();
}

static PHP_MINIT_FUNCTION(curl_hardening)
{
	/* ZEND_MOD_REQUIRED("curl") guarantees ext/curl started first. */
	if (curl_ce == NULL) {
		zend_error(E_CORE_WARNING, "curl_hardening: ext/curl is not available");
		return FAILURE;
	}

	/* A polyfill: define only what is missing. */
	if (zend_get_constant_str(ZEND_STRL("CURLOPT_OPENSOCKETFUNCTION")) != NULL) {
		curl_hardening_enabled = false;
		return SUCCESS;
	}

	/* Structural sanity check on the offset we rely on. The functional probe
	 * needs an object, which cannot be created this early: it runs on first use. */
	if (curl_ce->default_object_handlers == NULL
			|| curl_ce->default_object_handlers->offset == 0
			|| curl_ce->default_object_handlers->offset > 4096) {
		zend_error(E_CORE_WARNING, "curl_hardening: unexpected CurlHandle object layout");
		return FAILURE;
	}

	/* Hooks first: on failure, nothing is registered. */
	if (curl_hardening_hook_curl() == FAILURE) {
		zend_error(E_CORE_WARNING, "curl_hardening: could not hook ext/curl");
		return FAILURE;
	}

	register_curl_hardening_symbols(module_number);
	curl_address_family_ce = register_class_CurlAddressFamily();

	curl_hardening_enabled = true;
	return SUCCESS;
}

static PHP_MSHUTDOWN_FUNCTION(curl_hardening)
{
	curl_hardening_unhook_curl();

	return SUCCESS;
}

static const zend_module_dep curl_hardening_deps[] = {
	ZEND_MOD_REQUIRED("curl")
	ZEND_MOD_END
};

zend_module_entry curl_hardening_module_entry = {
	STANDARD_MODULE_HEADER_EX,
	NULL,
	curl_hardening_deps,
	"curl_hardening",
	NULL,
	PHP_MINIT(curl_hardening),
	PHP_MSHUTDOWN(curl_hardening),
	PHP_RINIT(curl_hardening),
	NULL,
	PHP_MINFO(curl_hardening),
	PHP_CURL_HARDENING_VERSION,
	PHP_MODULE_GLOBALS(curl_hardening),
	PHP_GINIT(curl_hardening),
	NULL,
	ZEND_MODULE_POST_ZEND_DEACTIVATE_N(curl_hardening),
	STANDARD_MODULE_PROPERTIES_EX
};

#ifdef COMPILE_DL_CURL_HARDENING
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(curl_hardening)
#endif
/* }}} */
