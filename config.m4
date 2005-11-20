dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(zeroconf)

APR_ADDTO(LT_LDFLAGS,-export-dynamic)

APACHE_MODULE(zeroconf, ZeroConf support, , , no, [
 AC_ARG_WITH(howl, APACHE_HELP_STRING(--with-howl=DIR,use a specific howl library),
  [
    if test "x$withval" != "xyes" && test "x$withval" != "x"; then
      ap_howl_base="$withval"
    fi
  ])
  if test "x$ap_howl_base" = "x"; then
    AC_MSG_CHECKING([for howl location])
    AC_CACHE_VAL(ap_cv_howl,[
      for dir in /usr/ /usr/local/ ; do
        if test -d $dir && test -f $dir/include/howl/howl.h; then
          ap_cv_howl=$dir
          break
        fi
      done
    ])
    ap_howl_base=$ap_cv_howl
    if test "x$ap_howl_base" = "x"; then
      enable_howl=no
      AC_MSG_RESULT([not found])
    else
      AC_MSG_RESULT([$ap_howl_base])
    fi
  fi
  APR_ADDTO(INCLUDES, [-I${ap_howl_base}/include/howl])
  APR_ADDTO(LDFLAGS, [-L${ap_howl_base}/lib])
  APR_ADDTO(LIBS, [-lhowl -lpthread])
])

APACHE_MODPATH_FINISH
