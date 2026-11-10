PHP_ARG_ENABLE([curl-hardening],
  [whether to enable curl_hardening support],
  [AS_HELP_STRING([--enable-curl-hardening],
    [Enable curl_hardening support])])

if test "$PHP_CURL_HARDENING" != "no"; then
  dnl Headers only. The extension calls into the libcurl ext/curl already
  dnl loaded, and must not be linked against one of its own: a second libcurl
  dnl in the process would be handed easy handles the first one created.
  PKG_CHECK_MODULES([CURL], [libcurl >= 7.61.0])
  PHP_EVAL_INCLINE([$CURL_CFLAGS])

  AC_DEFINE([HAVE_CURL_HARDENING], [1], [Define to 1 if curl_hardening is enabled])

  PHP_NEW_EXTENSION([curl_hardening], [curl_hardening.c], [$ext_shared])
  PHP_ADD_EXTENSION_DEP([curl_hardening], [curl])
fi
