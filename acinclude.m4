dnl limal-perl.m4
dnl $Id$
dnl
dnl Miscellaneous Perl checks
dnl Copied from yast2-perl-bindings/configure.in.in
dnl It is not cleaned up so it should stay local to this package
AC_DEFUN([LIMAL_PERL_CHECKS], [

AC_PROGRAM_PATH(PERL, perl)
if test -z "$PERL" ; then
    AC_MSG_ERROR(perl is missing; please install perl 5.x or later.)
fi
AC_SUBST(PERL)

## Find out what compiler/linker flags an embedded Perl interpreter needs
PERL_CFLAGS=`perl -MExtUtils::Embed -e 'ccopts'`
PERL_LDFLAGS=`perl -MExtUtils::Embed -e 'ldopts'`

AC_SUBST(PERL_CFLAGS)
AC_SUBST(PERL_LDFLAGS)

CFLAGS="${CFLAGS} ${PERL_CFLAGS}"
CXXFLAGS="${CXXFLAGS} ${PERL_CFLAGS}"

## Where to install modules
PERL_VENDORARCH=`perl -V:vendorarch | sed "s!.*='!!;s!'.*!!"`
AC_SUBST(PERL_VENDORARCH)

])
