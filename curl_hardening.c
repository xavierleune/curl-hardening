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
 *         function (CurlHandle $handle, int $purpose, CurlSocketAddress $address): ?CurlSocket { ... });
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
# include <unistd.h>
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
static zend_class_entry *curl_socket_address_ce;
static zend_class_entry *curl_socket_ce;
static zend_object_handlers curl_socket_object_handlers;

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

	return CURL_HARDENING_G(probe_state) > 0;
}
/* }}} */

/* {{{ Per-handle state
 *
 * ext/curl gives us nowhere to store anything on a CurlHandle, so every handle
 * the extension deals with gets a curl_hardening_handle, kept in a
 * request-scoped table keyed by object address and freed together with the
 * object. It is what libcurl's CURLOPT_OPENSOCKETDATA points at, which is how
 * the callback knows which handle performs the transfer.
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
	bool interface_set;           /* CURLOPT_INTERFACE is set */
	bool localport_set;           /* CURLOPT_LOCALPORT is set */
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

static curl_hardening_handle *curl_hardening_handle_find(zend_object *obj)
{
	return zend_hash_index_find_ptr(&CURL_HARDENING_G(handles), CURL_HARDENING_KEY(obj));
}

static curl_hardening_handle *curl_hardening_handle_get(zend_object *obj)
{
	curl_hardening_handle *hh = curl_hardening_handle_find(obj);

	if (hh == NULL) {
		hh = ecalloc(1, sizeof(curl_hardening_handle));
		hh->object = obj;
		zend_hash_index_add_new_ptr(&CURL_HARDENING_G(handles), CURL_HARDENING_KEY(obj), hh);
	}

	return hh;
}

static curl_socket_t curl_hardening_opensocket(void *clientp, curlsocktype purpose,
		struct curl_sockaddr *address);

/* libcurl's option is armed if and only if hh->state is set. */
static void curl_hardening_arm(curl_hardening_handle *hh)
{
	CURL *cp = curl_hardening_easy_handle(hh->object);

	if (cp != NULL) {
		curl_easy_setopt(cp, CURLOPT_OPENSOCKETFUNCTION, curl_hardening_opensocket);
		curl_easy_setopt(cp, CURLOPT_OPENSOCKETDATA, hh);
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

/* {{{ CurlSocket: a description, never a descriptor */
typedef struct {
	bool has_bind;
	int bind_family;
	socklen_t bind_len;
	struct sockaddr_storage bind_addr;
	zend_object std;
} curl_socket_object;

static inline curl_socket_object *curl_socket_from_obj(zend_object *obj)
{
	return (curl_socket_object *) ((char *) obj - offsetof(curl_socket_object, std));
}

static zend_object *curl_socket_create_object(zend_class_entry *ce)
{
	curl_socket_object *intern = zend_object_alloc(sizeof(curl_socket_object), ce);

	memset(intern, 0, offsetof(curl_socket_object, std));
	zend_object_std_init(&intern->std, ce);
	object_properties_init(&intern->std, ce);

	return &intern->std;
}

static zend_object *curl_socket_clone_object(zend_object *old)
{
	zend_object *new_obj = curl_socket_create_object(old->ce);

	zend_objects_clone_members(new_obj, old);
	memcpy(curl_socket_from_obj(new_obj), curl_socket_from_obj(old), offsetof(curl_socket_object, std));

	return new_obj;
}

PHP_METHOD(CurlSocket, bind)
{
	zend_string *address;
	zend_long port = 0;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_STR(address)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(port)
	ZEND_PARSE_PARAMETERS_END();

	if (port < 0 || port > 65535) {
		zend_argument_value_error(2, "must be between 0 and 65535");
		RETURN_THROWS();
	}

	curl_socket_object *intern = curl_socket_from_obj(Z_OBJ_P(ZEND_THIS));
	struct sockaddr_storage storage;
	memset(&storage, 0, sizeof(storage));

	/* inet_pton() stops at the first NUL: reject embedded ones explicitly. */
	bool valid = memchr(ZSTR_VAL(address), '\0', ZSTR_LEN(address)) == NULL;
	int family = AF_UNSPEC;
	socklen_t len = 0;

	if (valid) {
		struct sockaddr_in *in4 = (struct sockaddr_in *) &storage;
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) &storage;

		if (inet_pton(AF_INET, ZSTR_VAL(address), &in4->sin_addr) == 1) {
			in4->sin_family = family = AF_INET;
			in4->sin_port = htons((unsigned short) port);
			len = sizeof(*in4);
		} else if (inet_pton(AF_INET6, ZSTR_VAL(address), &in6->sin6_addr) == 1) {
			in6->sin6_family = family = AF_INET6;
			in6->sin6_port = htons((unsigned short) port);
			len = sizeof(*in6);
		} else {
			valid = false;
		}
	}

	if (!valid) {
		zend_argument_value_error(1, "must be a valid IPv4 or IPv6 address");
		RETURN_THROWS();
	}

	intern->has_bind = true;
	intern->bind_family = family;
	intern->bind_len = len;
	memcpy(&intern->bind_addr, &storage, sizeof(storage));
}

/* Creates the socket for a connection the callback allowed, as described. */
static curl_socket_t curl_hardening_create_socket(curl_hardening_handle *hh,
		const curl_socket_object *desc, const struct curl_sockaddr *address)
{
	if (desc->has_bind) {
		if (hh->interface_set || hh->localport_set) {
			/* libcurl binds again after us for these options: the second bind()
			 * would fail with an error far from its cause. */
			zend_throw_error(NULL,
				"CurlSocket::bind() cannot be used on a handle that sets CURLOPT_INTERFACE or CURLOPT_LOCALPORT");
			return CURL_SOCKET_BAD;
		}

		if (desc->bind_family != address->family) {
			/* Refuse this attempt only: on a dual stack host libcurl then tries
			 * the next address family, which the bind may well match. */
			return CURL_SOCKET_BAD;
		}
	}

	curl_socket_t fd = socket(address->family, address->socktype, address->protocol);

	if (fd != CURL_SOCKET_BAD && desc->has_bind
			&& bind(fd, (const struct sockaddr *) &desc->bind_addr, desc->bind_len) != 0) {
#ifdef PHP_WIN32
		closesocket(fd);
#else
		close(fd);
#endif
		fd = CURL_SOCKET_BAD;
	}

	return fd;
}
/* }}} */

/* {{{ CurlSocketAddress */
PHP_METHOD(CurlSocketAddress, __construct)
{
	/* Only reachable through reflection: the constructor is private. */
	zend_throw_error(NULL, "Cannot directly construct CurlSocketAddress");
}

static zend_long curl_hardening_sockaddr_port(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
		case AF_INET:
			return ntohs(((const struct sockaddr_in *) sa)->sin_port);
#ifdef AF_INET6
		case AF_INET6:
			return ntohs(((const struct sockaddr_in6 *) sa)->sin6_port);
#endif
		default:
			return 0;
	}
}

#ifdef AF_UNIX
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
		/* A pathname: libcurl counts the terminating NUL in addrlen. */
		len = zend_strnlen(sun->sun_path, len);
	}

	return zend_string_init(sun->sun_path, len, 0);
}
#endif

/* Builds the CurlSocketAddress for the callback. Returns false for anything
 * that cannot be described, which is then refused without calling it. */
static bool curl_hardening_socket_address(zval *zv, const struct curl_sockaddr *address)
{
	const char *family;
	zend_string *str;
	zend_long port = 0;

	switch (address->family) {
		case AF_INET:
		case AF_INET6:
			family = address->family == AF_INET ? "IpV4" : "IpV6";
			str = php_inet_ntop(&address->addr);
			if (str == NULL) {
				return false;
			}
			port = curl_hardening_sockaddr_port(&address->addr);
			break;
#ifdef AF_UNIX
		case AF_UNIX:
			family = "Unix";
			str = curl_hardening_unix_path(address);
			break;
#endif
		default:
			return false;
	}

	object_init_ex(zv, curl_socket_address_ce);
	zend_object *obj = Z_OBJ_P(zv);

	/* Readonly properties, in declaration order, written in place and marked
	 * initialized. */
	ZVAL_OBJ_COPY(OBJ_PROP_NUM(obj, 0), zend_enum_get_case_cstr(curl_address_family_ce, family));
	ZVAL_STR(OBJ_PROP_NUM(obj, 1), str);
	ZVAL_LONG(OBJ_PROP_NUM(obj, 2), port);
	for (uint32_t i = 0; i < 3; i++) {
		Z_PROP_FLAG_P(OBJ_PROP_NUM(obj, i)) &= ~(IS_PROP_UNINIT | IS_PROP_REINITABLE);
	}

	return true;
}
/* }}} */

/* {{{ The CURLOPT_OPENSOCKETFUNCTION trampoline */
static curl_socket_t curl_hardening_opensocket(void *clientp, curlsocktype purpose,
		struct curl_sockaddr *address)
{
	curl_hardening_handle *hh = (curl_hardening_handle *) clientp;
	curl_hardening_state *state = hh->state;

	/* Whatever cannot be described to the callback is refused without calling
	 * it: a policy must never be bypassed by an endpoint it was not shown.
	 * CURLSOCKTYPE_IPCXN is the only purpose libcurl currently uses; a future
	 * one may well not designate a destination at all. */
	if (UNEXPECTED(state == NULL || purpose != CURLSOCKTYPE_IPCXN)) {
		return CURL_SOCKET_BAD;
	}

	zval args[3], retval;

	if (!curl_hardening_socket_address(&args[2], address)) {
		return CURL_SOCKET_BAD;
	}

	/* The callback may replace or remove itself: keep this state alive. The
	 * handle is kept alive by the reference passed to the callback, and so is
	 * hh, which is only freed with its object. */
	curl_hardening_state_acquire(state);
	GC_ADDREF(hh->object);
	ZVAL_OBJ(&args[0], hh->object);
	ZVAL_LONG(&args[1], purpose);
	ZVAL_UNDEF(&retval);

	hh->in_callback = true;
	zend_call_known_fcc(&state->fcc, &retval, /* param_count */ 3, args, /* named_params */ NULL);
	hh->in_callback = false;

	curl_socket_t fd = CURL_SOCKET_BAD;

	/* retval is undefined when the callback threw: the connection is refused
	 * and the exception propagates out of curl_exec(). */
	if (!Z_ISUNDEF(retval)) {
		if (Z_TYPE(retval) == IS_OBJECT && Z_OBJCE(retval) == curl_socket_ce) {
			fd = curl_hardening_create_socket(hh, curl_socket_from_obj(Z_OBJ(retval)), address);
		} else if (Z_TYPE(retval) != IS_NULL) {
			zend_type_error("The CURLOPT_OPENSOCKETFUNCTION callback must return a CurlSocket or null");
		}
		zval_ptr_dtor(&retval);
	}

	zval_ptr_dtor(&args[0]);
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
	if (!curl_hardening_probe()) {
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

/* Tracks the options libcurl binds with after our callback returns. */
static void curl_hardening_record_option(zend_object *obj, zend_long option, zval *value)
{
	if (option != CURLOPT_INTERFACE && option != CURLOPT_LOCALPORT) {
		return;
	}

	curl_hardening_handle *hh = curl_hardening_handle_get(obj);

	if (option == CURLOPT_INTERFACE) {
		hh->interface_set = Z_TYPE_P(value) != IS_NULL;
	} else {
		hh->localport_set = zval_get_long(value) != 0;
	}
}
/* }}} */

/* {{{ Interception of ext/curl
 *
 * Installed at MINIT, removed at MSHUTDOWN, only when ext/curl does not already
 * provide the option. Each hook calls through to ext/curl for anything that is
 * not ours:
 *
 * - curl_setopt(), curl_setopt_array(): set CURLOPT_OPENSOCKETFUNCTION, and
 *   track CURLOPT_INTERFACE / CURLOPT_LOCALPORT;
 * - curl_reset(): drop the callback like any other option, and refuse to run
 *   from within it, as ext/curl does for its own callbacks -- libcurl's
 *   curl_easy_reset() performs no such check;
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
	zend_function *function;
	zif_handler original;
} curl_hardening_function_hook;

static ZEND_NAMED_FUNCTION(curl_hardening_setopt);
static ZEND_NAMED_FUNCTION(curl_hardening_setopt_array);
static ZEND_NAMED_FUNCTION(curl_hardening_reset);
static ZEND_NAMED_FUNCTION(curl_hardening_copy_handle);

enum { HOOK_SETOPT, HOOK_SETOPT_ARRAY, HOOK_RESET, HOOK_COPY_HANDLE, HOOK_COUNT };

static curl_hardening_function_hook curl_hardening_hooks[HOOK_COUNT] = {
	[HOOK_SETOPT]       = { "curl_setopt",       sizeof("curl_setopt") - 1,       curl_hardening_setopt,       NULL, NULL },
	[HOOK_SETOPT_ARRAY] = { "curl_setopt_array", sizeof("curl_setopt_array") - 1, curl_hardening_setopt_array, NULL, NULL },
	[HOOK_RESET]        = { "curl_reset",        sizeof("curl_reset") - 1,        curl_hardening_reset,        NULL, NULL },
	[HOOK_COPY_HANDLE]  = { "curl_copy_handle",  sizeof("curl_copy_handle") - 1,  curl_hardening_copy_handle,  NULL, NULL },
};

/* A callable copy of curl_setopt_array() still pointing at ext/curl, used to
 * apply the options on either side of ours in the order they were given. */
static zend_internal_function curl_hardening_orig_setopt_array_fn;

#define CURL_HARDENING_CALL_ORIGINAL(hook) \
	curl_hardening_hooks[hook].original(INTERNAL_FUNCTION_PARAM_PASSTHRU)

/* The option argument, when it is an int: the only form we have to recognise
 * without parsing the arguments ourselves, which would repeat any diagnostic
 * ext/curl emits for the calls we merely forward. */
static bool curl_hardening_arg_long(zend_execute_data *execute_data, uint32_t num, zend_long *value)
{
	if (ZEND_NUM_ARGS() < num) {
		return false;
	}

	zval *arg = ZEND_CALL_ARG(execute_data, num);
	ZVAL_DEREF(arg);
	if (Z_TYPE_P(arg) != IS_LONG) {
		return false;
	}

	*value = Z_LVAL_P(arg);
	return true;
}

static ZEND_NAMED_FUNCTION(curl_hardening_setopt)
{
	zend_long option;

	if (!curl_hardening_arg_long(execute_data, 2, &option) || option != CURLOPT_OPENSOCKETFUNCTION) {
		CURL_HARDENING_CALL_ORIGINAL(HOOK_SETOPT);

		if (Z_TYPE_P(return_value) == IS_TRUE && curl_hardening_arg_long(execute_data, 2, &option)) {
			zval *zid = ZEND_CALL_ARG(execute_data, 1);
			zval *value = ZEND_CALL_ARG(execute_data, 3);
			ZVAL_DEREF(zid);
			ZVAL_DEREF(value);
			curl_hardening_record_option(Z_OBJ_P(zid), option, value);
		}
		return;
	}

	zval *zid, *zvalue;

	ZEND_PARSE_PARAMETERS_START(3, 3)
		Z_PARAM_OBJECT_OF_CLASS(zid, curl_ce)
		Z_PARAM_LONG(option)
		Z_PARAM_ZVAL(zvalue)
	ZEND_PARSE_PARAMETERS_END();

	RETURN_BOOL(curl_hardening_set_callback(Z_OBJ_P(zid), zvalue, /* is_array_config */ false));
}

/* Applies a run of options that are not ours through ext/curl. The segment is
 * a counted reference: an exception thrown by ext/curl captures it in its
 * trace, so the caller must release it, never clear or destroy it in place. */
static bool curl_hardening_apply_segment(zval *zid, zval *segment)
{
	if (zend_hash_num_elements(Z_ARRVAL_P(segment)) == 0) {
		return true;
	}

	zval params[2], retval;
	ZVAL_COPY_VALUE(&params[0], zid);
	ZVAL_COPY_VALUE(&params[1], segment);
	ZVAL_UNDEF(&retval);

	zend_call_known_function((zend_function *) &curl_hardening_orig_setopt_array_fn,
		NULL, NULL, &retval, 2, params, NULL);

	bool ok = Z_TYPE(retval) == IS_TRUE;
	zval_ptr_dtor(&retval);

	if (ok) {
		zend_ulong option;
		zval *value;
		ZEND_HASH_FOREACH_NUM_KEY_VAL(Z_ARRVAL_P(segment), option, value) {
			curl_hardening_record_option(Z_OBJ_P(zid), (zend_long) option, value);
		} ZEND_HASH_FOREACH_END();
	}

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

		if (Z_TYPE_P(return_value) == IS_TRUE && arr != NULL && Z_TYPE_P(arr) == IS_ARRAY) {
			zval *zid = ZEND_CALL_ARG(execute_data, 1);
			zend_ulong option;
			zval *value;
			ZVAL_DEREF(zid);
			ZEND_HASH_FOREACH_NUM_KEY_VAL(Z_ARRVAL_P(arr), option, value) {
				curl_hardening_record_option(Z_OBJ_P(zid), (zend_long) option, value);
			} ZEND_HASH_FOREACH_END();
		}
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
			ok = curl_hardening_apply_segment(zid, &segment)
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
		ok = curl_hardening_apply_segment(zid, &segment);
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
		hh->interface_set = false;
		hh->localport_set = false;
		curl_hardening_state_release(state);
	}
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

	curl_hardening_handle *to = curl_hardening_handle_get(dst);
	to->interface_set = from->interface_set;
	to->localport_set = from->localport_set;

	if (from->state != NULL) {
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
	curl_hardening_handle *hh = NULL;

	if (CURL_HARDENING_G(active)) {
		hh = curl_hardening_handle_find(object);
		if (hh != NULL) {
			zend_hash_index_del(&CURL_HARDENING_G(handles), CURL_HARDENING_KEY(object));
		}
	}

	/* Runs curl_easy_cleanup(): once it returns libcurl no longer reaches hh,
	 * and hh and its state can go. */
	curl_hardening_orig_free_obj(object);

	if (hh != NULL) {
		curl_hardening_state_release(hh->state);
		efree(hh);
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

	for (int i = 0; i < HOOK_COUNT; i++) {
		zend_function *fn = zend_hash_str_find_ptr(CG(function_table),
			curl_hardening_hooks[i].name, curl_hardening_hooks[i].name_len);
		if (fn == NULL || fn->type != ZEND_INTERNAL_FUNCTION) {
			return FAILURE;
		}
		curl_hardening_hooks[i].function = fn;
	}

	memcpy(&curl_hardening_orig_setopt_array_fn,
		&curl_hardening_hooks[HOOK_SETOPT_ARRAY].function->internal_function,
		sizeof(zend_internal_function));

	for (int i = 0; i < HOOK_COUNT; i++) {
		zend_internal_function *fn = &curl_hardening_hooks[i].function->internal_function;
		curl_hardening_hooks[i].original = fn->handler;
		fn->handler = curl_hardening_hooks[i].hook;
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
	for (int i = 0; i < HOOK_COUNT; i++) {
		if (curl_hardening_hooks[i].function != NULL) {
			curl_hardening_hooks[i].function->internal_function.handler = curl_hardening_hooks[i].original;
			curl_hardening_hooks[i].function = NULL;
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
	/* Request scoped: its buckets come from the request heap. */
	zend_hash_init(&CURL_HARDENING_G(handles), 8, NULL, NULL, 0);
	CURL_HARDENING_G(active) = true;

	return SUCCESS;
}

static PHP_RSHUTDOWN_FUNCTION(curl_hardening)
{
	if (!curl_hardening_enabled) {
		return SUCCESS;
	}

	HashTable *handles = &CURL_HARDENING_G(handles);
	curl_hardening_handle *hh;

	/* Handles still referenced now are freed later by the executor, after us.
	 * Disarm them all first, while every one of them is still alive. */
	ZEND_HASH_FOREACH_PTR(handles, hh) {
		if (hh->state != NULL) {
			curl_hardening_disarm(hh->object);
		}
	} ZEND_HASH_FOREACH_END();

	/* Releasing a callback may free the last reference to a CurlHandle: from
	 * here on, free_obj must leave the table alone. */
	CURL_HARDENING_G(active) = false;

	ZEND_HASH_FOREACH_PTR(handles, hh) {
		curl_hardening_state_release(hh->state);
		efree(hh);
	} ZEND_HASH_FOREACH_END();

	zend_hash_destroy(handles);

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

	register_curl_hardening_symbols(module_number);
	curl_address_family_ce = register_class_CurlAddressFamily();
	curl_socket_address_ce = register_class_CurlSocketAddress();
	curl_socket_ce = register_class_CurlSocket();

	curl_socket_ce->create_object = curl_socket_create_object;
	memcpy(&curl_socket_object_handlers, &std_object_handlers, sizeof(zend_object_handlers));
	curl_socket_object_handlers.offset = offsetof(curl_socket_object, std);
	curl_socket_object_handlers.clone_obj = curl_socket_clone_object;
	curl_socket_ce->default_object_handlers = &curl_socket_object_handlers;

	if (curl_hardening_hook_curl() == FAILURE) {
		zend_error(E_CORE_WARNING, "curl_hardening: could not hook ext/curl");
		return FAILURE;
	}

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
	PHP_RSHUTDOWN(curl_hardening),
	PHP_MINFO(curl_hardening),
	PHP_CURL_HARDENING_VERSION,
	PHP_MODULE_GLOBALS(curl_hardening),
	PHP_GINIT(curl_hardening),
	NULL,
	NULL,
	STANDARD_MODULE_PROPERTIES_EX
};

#ifdef COMPILE_DL_CURL_HARDENING
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(curl_hardening)
#endif
/* }}} */
