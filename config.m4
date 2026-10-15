PHP_ARG_ENABLE([curl-hardening],
  [whether to enable curl_hardening support],
  [AS_HELP_STRING([--enable-curl-hardening],
    [Enable curl_hardening support])])

if test "$PHP_CURL_HARDENING" != "no"; then
  PKG_CHECK_MODULES([CURL], [libcurl >= 7.61.0])
  PHP_EVAL_LIBLINE([$CURL_LIBS], [CURL_SHARED_LIBADD])
  PHP_EVAL_INCLINE([$CURL_CFLAGS])

  AC_DEFINE([HAVE_CURL_HARDENING], [1], [Define to 1 if curl_hardening is enabled])

  PHP_NEW_EXTENSION([curl_hardening], [curl_hardening.c], [$ext_shared])
  PHP_SUBST([CURL_SHARED_LIBADD])
  PHP_ADD_EXTENSION_DEP([curl_hardening], [curl])
fi
