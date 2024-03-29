dnl -*- Mode: sh -*-
dnl
dnl configure.ac - top level autoconf file for Lasso
dnl (Process this file with autoconf to produce a configure script.)
dnl
dnl 
dnl See COPYING at the top of this package for the full license terms.
dnl 
dnl 

dnl Declare package and package version.
dnl (r-c).a.r
dnl - First number is the lowest supported API version number.
dnl - Second number is the number of supported API versions where API version >
dnl   first number.
dnl - Third number is the current API version implementation version number.
dnl See libtool explanations about current, age and release, later in this file.
AC_INIT([lasso], m4_esyscmd([tools/git-version-gen .tarball-version]), lasso-devel@lists.labs.libre-entreprise.org)
dnl Check if autoconf ver > 2.53
AC_PREREQ(2.53)
AC_CONFIG_MACRO_DIR([m4])
dnl Perform only subset commands and variable relevant to the host type.
AC_CANONICAL_HOST
AC_CANONICAL_SYSTEM
dnl Check existence of a relative pathed source file.
AC_CONFIG_SRCDIR(lasso/lasso.c)
dnl Copy stamp REVISIO-INFO in the configure script.
AC_REVISION($Revision$)

dnl Run many macros mostly needed by configure.ac.
AM_INIT_AUTOMAKE([foreign tar-pax])
dnl Support automake 1.11 silent mode
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
m4_ifdef([AM_SILENT_RULES],[HAVE_AM_SILENT_RULES=yes])
AM_CONDITIONAL(HAVE_AM_SILENT_RULES, test x$HAVE_AM_SILENT_RULES != x)
dnl Create rules to automaticaly regenerate the config header.
AM_CONFIG_HEADER([config.h lasso/lasso_config.h])
dnl Add --enable-maintainer-mode option to configure.
AM_MAINTAINER_MODE([enable])

dnl ==========================================================================
dnl Perform host specific configuration
dnl ==========================================================================
NULL=

### Sun Java environment needs to be told about platform...
SUN_EXTRA_INCLUDE=
case "${host}" in
    *-pc-mingw32)
        SUN_EXTRA_INCLUDE="win32" 
        ;;
    *-pc-cygwin)
        SUN_EXTRA_INCLUDE="win32" 
        ;;
    *linux*)
        SUN_EXTRA_INCLUDE="linux"
        ;;
    *solaris*)
        SUN_EXTRA_INCLUDE="solaris"
        ;;
esac

### adapting build environment for different platforms...
MINGW=0
DARWIN=0
case "${host}" in
    *aix*)
        CFLAGS="${CFLAGS} -D_ALL_SOURCE"
        ;;
    *-pc-mingw32)
        case "${build}" in
            *-pc-cygwin)
                CC="gcc -mno-cygwin"
                CFLAGS="${CFLAGS} -D_MSC_VER -DIN_LASSO -DMINGW -DWIN32 -D_WIN32 -I/usr/local/include"
                LDFLAGS="${LDFLAGS} -L/usr/local/lib"
                MINGW=1
                ;;
        esac
        ;;
    *darwin*)
        DARWIN=1
        ;;
esac

# OSX Fink
if test -d /sw/bin ; then
  PATH=$PATH:/sw/bin
fi

dnl
dnl Check for programs
dnl
AC_PROG_CC
AM_CFLAGS=""
AC_HEADER_STDC
LT_AC_PROG_RC
AC_EXEEXT
AC_PROG_CC_C_O
AM_SANITY_CHECK
AC_PROG_AWK
AC_PROG_LN_S
AC_LIBTOOL_WIN32_DLL
AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)
AS_COMPILER_FLAGS(WARNING_FLAGS, "-Wall -Wextra -Wno-missing-field-initializers -Wno-unused-parameter -Wold-style-definition -Wdeclaration-after-statement -Wmissing-declarations -Wredundant-decls -Wmissing-noreturn -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Winline -Wformat-nonliteral -Wformat-security -Wswitch-enum -Wswitch-default -Winit-self -Wmissing-include-dirs -Wundef -Waggregate-return -Wmissing-format-attribute -Wnested-externs")

dnl Find tar command for make dist
AC_CHECK_PROGS(TAR, gnutar gtar tar)

dnl Check existence of binding programs
AC_CHECK_CLASSPATH
AC_PROG_JAVAC
AC_PROG_JAVA
AC_PROG_JAVAH
AC_PROG_JAR
DPS_XTRA_CLASSPATH(CLASSPATH_JUNIT, junit.framework.Test, junit.jar)
old_cp=$CLASSPATH
export CLASSPATH=${CLASSPATH}:${CLASSPATH_JUNIT}
AC_CHECK_JUNIT
if test "x$old_cp" = "x"; then
    unset CLASSPATH
else
    $CLASSPATH=$old_cp
fi
unset old_cp
dnl AC_CHECK_PROGS(JAVA, gij java)
dnl AC_CHECK_PROGS(JAVAC, gcj javac)
dnl AC_CHECK_PROGS(JAVAH, gjavah gcjh javah)
dnl AC_CHECK_PROGS(JAR, fastjar jar)

AC_CHECK_PROGS(PERL, perl)
AC_CHECK_PROGS(PHP5, php5 php)
AC_CHECK_PROGS(PHP5_CONFIG, php-config5 php-config)
AC_CHECK_PROGS(PHP7, php7.4 php7.3 php7.2 php7.1 php7.0 php7 php)
AC_CHECK_PROGS(PHP7_CONFIG, php-config7.4 php-config7.3 php-config7.2 php-config7.1 php-config7.0 php-config7 php-config)
AC_CHECK_PROGS(PYTHON, python3 python python2)
AC_CHECK_PROGS(SWIG, swig)

dnl Make sure we have an ANSI compiler
test "z$U" != "z" && AC_MSG_ERROR(Compiler not ANSI compliant)

dnl Check for variadic macros
AC_CACHE_CHECK([for variadic cpp macros],
    [ac_cv_cpp_variadic_macros],
    [AC_TRY_COMPILE(
         [#include <stdio.h>
          #define a(b,c...) printf(b,##c)],
         [a("foo");a("%s","bar");a("%s%s","baz","quux");],
         ac_cv_cpp_variadic_macros=yes,
         ac_cv_cpp_variadic_macros=no)])
if test "x${ac_cv_cpp_variadic_macros}" != "xno"; then
    AC_DEFINE(HAVE_VARIADIC_MACROS, 1, Support for variadic macros)
fi


dnl ==========================================================================
dnl Version Super.Size.Me.L
dnl ==========================================================================

changequote(<<, >>)dnl
VERSION_MAJOR=`echo $VERSION | $SED -e 's/^\([^\.]*\)\.\([^\.]*\)\.\(.*\)$/\1/'`
VERSION_MINOR=`echo $VERSION | $SED -e 's/^\([^\.]*\)\.\([^\.]*\)\.\(.*\)$/\2/'`
VERSION_RELEASE=`echo $VERSION | $SED -e 's/^\([^\.]*\)\.\([^\.]*\)\.\([0-9]*\).*$/\3/'`
changequote([, ])dnl
VERSION_UNDERSCORED=`echo $VERSION | $SED -e 's/\./_/g'`
AC_SUBST(VERSION_UNDERSCORED)


dnl Add versionning & package defines to lasso_.h
AC_DEFINE_UNQUOTED(LASSO_VERSION_MAJOR, $VERSION_MAJOR, [Major version number])
AC_DEFINE_UNQUOTED(LASSO_VERSION_MINOR, $VERSION_MINOR, [Minor version number])
AC_DEFINE_UNQUOTED(LASSO_VERSION_SUBMINOR, $VERSION_RELEASE, [Release version number])

dnl Create an XMLSEC version number for tests
AC_DEFINE(LASSO_XMLSEC_VERSION_NUMBER, [(((XMLSEC_VERSION_MAJOR * 0x010000) + (XMLSEC_VERSION_MINOR * 0x0100) + (XMLSEC_VERSION_SUBMINOR * 0x01)))], [XMLSEC Version number])
AH_BOTTOM([#include <xmlsec/version.h>])

dnl Dirty hack in order to have dynamic resource version numbering.
WINDOWS_VERSION=`echo $VERSION_MAJOR,$VERSION_MINOR,$VERSION_RELEASE,0`
AC_SUBST(WINDOWS_VERSION)

dnl CURRENT, REVISION, AGE
dnl - library source changed -> increment REVISION
dnl - interfaces added/removed/changed -> increment CURRENT, REVISION = 0
dnl - interfaces added -> increment AGE
dnl - interfaces removed -> AGE = 0

# syntax: CURRENT[:REVISION[:AGE]]
# So if M=major, m=minor, r=release:
# c = M + a = M + m;
# m = a
# r = r
current=`expr $VERSION_MAJOR + $VERSION_MINOR`
LASSO_VERSION_INFO="18:2:15"
AC_SUBST(LASSO_VERSION_INFO)

dnl Compute the minimal supported ABI version for Win32 scripts and resources files.
minimal_version=`echo $LASSO_VERSION_INFO | $AWK -F: '{printf("%d\n",$1-$3)};'`
UPCASED_DLL_FILENAME="LIBLASSO-$minimal_version.DLL"
DLL_FILENAME="liblasso-$minimal_version.dll"
AC_SUBST(UPCASED_DLL_FILENAME)
AC_SUBST(DLL_FILENAME)

dnl Detect available languages binding.
languages_available=


# ------------
# JAVA binding
# ------------

dnl Check if java is explicitly disabled.
AC_ARG_ENABLE(java, [  --enable-java          enable the Java binding],,
              enable_java="no")
AC_ARG_WITH(java-home,
            [  --with-java-home=(JAVA_HOME)  set the full path to the java home directory.])
SUN=no

dnl If the java compiler seems to be a Sun JDK-like compile (Kaffe, Sun JDK...)
if test "x$JAVAC" = "xjavac"; then
    JAVAC_PATH=`which $JAVAC`
    if test "x$with_java_home" = "x"; then
	    with_java_home=`readlink -f $JAVAC_PATH | sed s#/bin/.*##`
    fi
    dnl If we have a java compiler
    dnl need to change quotes to allow square brackets
    changequote(<<, >>)dnl
    JAVA_VERSION=`$JAVA -version 2>&1 | $SED -ne 's/\(openjdk\|java\) \(full\)*version "\([^"]*\)".*/\3/p' 2>/dev/null`
    changequote([, ])dnl
    dnl If no java version found, perphas it is a kaffee environment...
    if test "x$JAVA_VERSION" = x; then
        JAVA_VERSION=`$JAVA -version 2>&1 | grep "Java Version" | $SED 's/^.*Java Version: //g'`
        dnl If the java environment is kaffe, specify the JAVA_INCLUDE directory.
    else
        dnl We assume it is a SUN environment.
        SUN=yes
    fi
    CLASSPATH_OPT="-classpath"
fi

if test "x$with_java_home" != x; then
    JAVA_INCLUDE="$with_java_home/include"
fi

if ! test -f "$JAVA_INCLUDE/jni.h"; then
    JAVA_VERSION=""
fi

dnl GNU java environment
if test "x$JAVAH" = "xgcjh" || test "x$JAVAH" = "xgjavah"  ; then
    dnl JNI compatible header files. (not used with SWIG.)
    JAVAH_FLAGS="-jni"
    JAVA_INCLUDE=""
fi

dnl If the java compiler is the GNU Java Compiler.
if echo "$JAVAC" | grep -q "gcj"; then
    changequote(<<, >>)dnl
    JAVA_VERSION=`$JAVAC --version 2>&1 | $SED -ne 's/gcj[^[:blank:]]* ([^)]*) \([^ ]*\).*/\1/p' 2>/dev/null`
    MAJOR=`echo $JAVA_VERSION | sed 's/.*[^[:digit:]]\?\([[:digit:]]\+\)\.[[:digit:]]\+\.[[:digit:]]\+/\1/'`
    MINOR=`echo $JAVA_VERSION | sed 's/.*[^[:digit:]]\?[[:digit:]]\+\.\([[:digit:]]\+\)\.[[:digit:]]\+/\1/'`
    RELEASE=`echo $JAVA_VERSION | sed 's/.*[^[:digit:]]\?[[:digit:]]\+\.[[:digit:]]\+\.\([[:digit:]]\+\).*/\1/'`
    changequote([, ])dnl
    dnl Byte-compiled .class file
    if test $MAJOR -gt 4 -o \( $MAJOR -eq 4 -a $MINOR -gt 1 \) -o \( $MAJOR -eq 4 -a $MINOR -eq 1 -a $RELEASE -ge 3 \); then
        JAVAC_FLAGS="-fsource=1.4 -ftarget=1.4"
    fi
    unset MAJOR
    unset MINOR
    unset RELEASE
    dnl Checking for jni.h if gcj is the java interpreter.
    AC_CHECK_HEADERS([jni.h], [], [JAVA_VERSION=""])
    CLASSPATH_OPT="--classpath"
fi

dnl Now transform JAVA_INCLUDE in CFLAG option if applicable.
if test "X$JAVA_INCLUDE" != "X"; then
    dnl If it is a sun environment
    if test "x$SUN" = "xyes"; then
        JAVA_INCLUDE="$JAVA_INCLUDE -I$JAVA_INCLUDE/$SUN_EXTRA_INCLUDE"
    fi
    JAVA_INCLUDE=-I$JAVA_INCLUDE
fi

dnl If we found a java version information, we have java compilation environment.
if test "X$JAVA_VERSION" != "X" && test "X$JAR" != "X" && test "x$JAVAH" != "x"; then
  languages_available="$languages_available $JAVA($JAVA_VERSION)"
else
  enable_java=no
  JAVA_VERSION=""
fi

dnl Support JNI under MacOsX
if test  "$DARWIN" = 1; then
    JNI_EXTRA_LDFLAGS="-shrext .jnilib"
fi

dnl Conditional java sub dir test.
AM_CONDITIONAL([JAVA_ENABLED],[test "x$enable_java" = "xyes"])
AM_CONDITIONAL([JUNIT_ENABLED],[test "x$JUNIT" != "x"])
AC_SUBST(JAVA_VERSION)
AC_SUBST(JAVAC_FLAGS)
AC_SUBST(JAVAH_FLAGS)
AC_SUBST(JAVA_INCLUDE)
AC_SUBST(CLASSPATH_OPT)
JDK_INCLUDE=$JAVA_INCLUDE
AC_SUBST(JDK_INCLUDE)
AC_SUBST(JNI_EXTRA_LDFLAGS)


# --------------
# Python binding
# --------------

dnl Check if python is explicitly disabled.
AC_ARG_ENABLE(python, [  --disable-python        disable the Python binding],,
              enable_python="yes")

dnl Check if user passed a specific python program.
AC_ARG_WITH(python,
            [  --with-python=(PYTHON)  set the full path to the python program to use.])

dnl specific program passed, set PYTHON to it.
if test "X$with_python" != "X"; then
    PYTHON=$with_python
fi


dnl need to change quotes to allow square brackets
changequote(<<, >>)dnl
PYTHON_VERSION=`$PYTHON -c 'from distutils import sysconfig ; print(sysconfig.get_config_var("VERSION"))'`
changequote([, ])dnl

test "x$PYTHON" != "x" || AC_MSG_ERROR(Python must be installed to compile lasso)

AC_MSG_CHECKING(for Python development files)
dnl Check if we were be able to extract a good version number.
if test "X$PYTHON_VERSION" != "X"; then
    changequote(<<, >>)dnl
    PYTHON_INC=`$PYTHON -c 'from distutils import sysconfig ; print(sysconfig.get_python_inc())'`
    PYTHON_LIB=`$PYTHON -c 'from distutils import sysconfig ; print(sysconfig.get_python_lib(1))'`
    changequote([, ])dnl
    PYTHON_H=$PYTHON_INC/Python.h
    if test -f $PYTHON_H; then
            PY_CFLAGS="-I$PYTHON_INC"
            PY_MAKEFILE=`$PYTHON -c 'from distutils import sysconfig ; print(sysconfig.get_makefile_filename())'`
            PY_OTHER_LIBS=`$SED -n -e 's/^LIBS=\(.*\)/\1/p' $PY_MAKEFILE`
            PY_EXTRA_LIBS="$PY_LOCALMODLIBS $PY_BASEMODLIBS $PY_OTHER_LIBS"
            dnl this extracts the $libdir out of python lib directory,
            dnl replacing it by our own.
            PY_SUFFIX_LIB=`echo $PYTHON_LIB | $SED -e 's/.*python/python/'`
            PY_SITE_PACKAGES="\${libdir}/$PY_SUFFIX_LIB"
            AC_SUBST(PYTHON)
            AC_SUBST(PY_LIB_LOC)
            AC_SUBST(PY_CFLAGS)
            AC_SUBST(PY_EXTRA_LIBS)
            AC_SUBST(PY_DYNLOAD)
            AC_SUBST(PY_LIB_A)
            AC_SUBST(PY_SITE_PACKAGES)
            languages_available="$languages_available python($PYTHON_VERSION)"
    else
            enable_python=no
    fi
else
	enable_python=no
fi
AM_CONDITIONAL([PYTHON_ENABLED],[test "x$enable_python" = "xyes"])
AC_MSG_RESULT($enable_python)
AC_SUBST(PYTHON_VERSION)

# -----------
# PHP 5 binding
# -----------

dnl Check if php is explicitly enabled.
AC_ARG_ENABLE(php5, [  --enable-php5          enable the PHP 5 binding],,
              enable_php5="yes")

AC_ARG_WITH(php5-config,
            [  --with-php5-config=(PHP5_CONFIG)      Specify full path to php-config5.])

AC_ARG_ENABLE(php5-force, [  --enable-php5-force     always enable of the PHP 5 binding (win32)],
              [ENABLE_PHP5_FORCE="yes"],
              [ENABLE_PHP5_FORCE="no"])


dnl Check if user passed a specific php-config program.
if test "X$with_php5_config" != "X" ; then
    PHP5_CONFIG=$with_php5_config
fi

if test "X$PHP5_CONFIG" != "X" ; then
  PHP5_INCLUDES=`$PHP5_CONFIG --includes`
  PHP5_LDFLAGS=`$PHP5_CONFIG --ldflags`
  PHP5_LIBS=`$PHP5_CONFIG --libs`
  PHP5_PREFIX=`$PHP5_CONFIG --prefix`
  PHP5_QUOTED_PREFIX=$(echo $PHP5_PREFIX | $SED 's/\//\\\//g')
  PHP5_UNPREFIXED_EXTENSION_DIR=$($PHP5_CONFIG --extension-dir | $SED "s/$PHP5_QUOTED_PREFIX//g")
else
  # We assume PHP are in /usr/local directory.
  if test $MINGW -eq 1; then 
    CFLAGS="$CFLAGS -DZTS -DZEND_WIN32 -DWIN32 -D_MBCS"
  fi
  PHP5_INCLUDES="-I/usr/local/include/php5 -I/usr/local/include/php5/main -I/usr/local/include/php5/Zend -I/usr/local/include/php5/TSRM -I/usr/local/include/php5/win32"
  PHP5_LDFLAGS=
  PHP5_LIBS="-lphp5ts -lxmlparse -lxmltok"
  PHP5_UNPREFIXED_EXTENSION_DIR=
  PHP5_PREFIX=
fi

AC_ARG_WITH(php5-include-dir,
            [  --with-php5-include-dir=(PHP5_INCLUDE_DIR)      Specify full path to php 5 include dir.],
            [PHP5_INCLUDE_DIR="$withval"],[PHP5_INCLUDE_DIR=${datadir}/php])

AC_ARG_WITH(php5-config-dir,
            [  --with-php5-config-dir=(PHP5_CONFIG_DIR)      Specify full path to php 5 config dir.],
            [PHP5_CONFIG_DIR="$withval"],[PHP5_CONFIG_DIR=${sysconfdir}/php5/conf.d/])

AC_SUBST(PHP5_INCLUDES)
AC_SUBST(PHP5_LDFLAGS)
AC_SUBST(PHP5_LIBS)
AC_SUBST(PHP5_UNPREFIXED_EXTENSION_DIR)
AC_SUBST(PHP5_EXTENSION_DIR)
AC_SUBST(PHP5_PREFIX)
AC_SUBST(PHP5_INCLUDE_DIR)
AC_SUBST(PHP5_CONFIG_DIR)

AC_MSG_CHECKING(for PHP 5 development files)
if $PHP5_CONFIG --version | grep -q "^5" || test "x$ENABLE_PHP5_FORCE" = "xyes"
then
	PHP5_VERSION=`$PHP5_CONFIG --version 2> /dev/null`
	languages_available="$languages_available php5($PHP5_VERSION)"
else
	enable_php5=no
fi

AC_MSG_RESULT($enable_php5)
AM_CONDITIONAL([PHP5_ENABLED], [test "x$enable_php5" = "xyes"])
AC_SUBST(PHP5_VERSION)


# -----------
# PHP 7 binding
# -----------

dnl Check if php is explicitly enabled.
AC_ARG_ENABLE(php7, [  --enable-php7          enable the PHP 7 binding],,
              enable_php7="yes")

AC_ARG_WITH(php7-config,
            [  --with-php7-config=(PHP7_CONFIG)      Specify full path to php-config7.])

AC_ARG_ENABLE(php7-force, [  --enable-php7-force     always enable of the PHP 7 binding (win32)],
              [ENABLE_PHP7_FORCE="yes"],
              [ENABLE_PHP7_FORCE="no"])


dnl Check if user passed a specific php-config program.
if test "X$with_php7_config" != "X" ; then
    PHP7_CONFIG=$with_php7_config
fi

if test "X$PHP7_CONFIG" != "X" ; then
  PHP7_INCLUDES=`$PHP7_CONFIG --includes`
  PHP7_LDFLAGS=`$PHP7_CONFIG --ldflags`
  PHP7_LIBS=`$PHP7_CONFIG --libs`
  PHP7_PREFIX=`$PHP7_CONFIG --prefix`
  PHP7_QUOTED_PREFIX=$(echo $PHP7_PREFIX | $SED 's/\//\\\//g')
  PHP7_UNPREFIXED_EXTENSION_DIR=$($PHP7_CONFIG --extension-dir | $SED "s/$PHP7_QUOTED_PREFIX//g")
else
  # We assume PHP are in /usr/local directory.
  if test $MINGW -eq 1; then 
    CFLAGS="$CFLAGS -DZTS -DZEND_WIN32 -DWIN32 -D_MBCS"
  fi
  PHP7_INCLUDES="-I/usr/local/include/php7 -I/usr/local/include/php7/main -I/usr/local/include/php7/Zend -I/usr/local/include/php7/TSRM -I/usr/local/include/php7/win32"
  PHP7_LDFLAGS=
  PHP7_LIBS="-lphp7ts -lxmlparse -lxmltok"
  PHP7_UNPREFIXED_EXTENSION_DIR=
  PHP7_PREFIX=
fi

AC_ARG_WITH(php7,
            [  --with-php7=(PHP)      Specify full path to php 7 executable.],
            [PHP7="$withval"],[PHP7_INCLUDE_DIR=php7])

AC_ARG_WITH(php7-include-dir,
            [  --with-php7-include-dir=(PHP7_INCLUDE_DIR)      Specify full path to php 7 include dir.],
            [PHP7_INCLUDE_DIR="$withval"],[PHP7_INCLUDE_DIR=${datadir}/php])

AC_ARG_WITH(php7-config-dir,
            [  --with-php7-config-dir=(PHP7_CONFIG_DIR)      Specify full path to php 7 config dir.],
            [PHP7_CONFIG_DIR="$withval"],[PHP7_CONFIG_DIR=${sysconfdir}/php7/conf.d/])

AC_SUBST(PHP7_INCLUDES)
AC_SUBST(PHP7_LDFLAGS)
AC_SUBST(PHP7_LIBS)
AC_SUBST(PHP7_UNPREFIXED_EXTENSION_DIR)
AC_SUBST(PHP7_EXTENSION_DIR)
AC_SUBST(PHP7_PREFIX)
AC_SUBST(PHP7_INCLUDE_DIR)
AC_SUBST(PHP7_CONFIG_DIR)

AC_MSG_CHECKING(for PHP 7 development files)
if $PHP7_CONFIG --version | grep -q "^7" || test "x$ENABLE_PHP7_FORCE" = "xyes"
then
	PHP7_VERSION=`$PHP7_CONFIG --version 2> /dev/null`
	languages_available="$languages_available php7($PHP7_VERSION)"
else
	enable_php7=no
fi

AC_MSG_RESULT($enable_php7)
AM_CONDITIONAL([PHP7_ENABLED], [test "x$enable_php7" = "xyes"])
AC_SUBST(PHP7_VERSION)


### # ----------
### # C# binding (disabled for the moment)
### # ----------
### 
### AC_ARG_ENABLE(csharp, [  --disable-csharp        disable the C Sharp binding],,
###               enable_csharp="yes")
### 
### AC_ARG_WITH(cil-interpreter, [  --with-cil-interpreter=path     set location of CIL interpreter for CSharp],[CSHARPBIN="$withval"], [CSHARPBIN=])
### AC_ARG_WITH(csharp-compiler, [  --with-csharp-compiler=path     set location of CSharp compiler],[CSHARPCOMPILERBIN="$withval"], [CSHARPCOMPILERBIN=])
### 
### if test -z "$CSHARPCOMPILERBIN" ; then
###   case $host in
###   *-*-cygwin* | *-*-mingw*)
###     AC_CHECK_PROGS(CSHARPCOMPILER, mcs.bat cscc csc);;
###   *)AC_CHECK_PROGS(CSHARPCOMPILER, mcs cscc);;
###   esac
### else
###   CSHARPCOMPILER="$CSHARPCOMPILERBIN"
### fi
### 
### CSHARPPATHSEPARATOR="/"
### CSHARPCYGPATH_W=echo
### if test -z "$CSHARPBIN" ; then
###   #languages_available="$languages_available C#($CSHARPCOMPILER)"
###   CSHARPCILINTERPRETER=""
###   if test "cscc" = "$CSHARPCOMPILER" ; then
###     AC_CHECK_PROGS(CSHARPCILINTERPRETER, ilrun)
###   else
###     if test "mcs" = "$CSHARPCOMPILER"; then
###       # Check that mcs is the C# compiler and not the Unix mcs utility by examining the output of 'mcs --version'
###       # The Mono compiler should emit: Mono C# compiler version a.b.c.d
###       csharp_version_raw=`(mcs --version) 2>/dev/null`
###       csharp_version_searched=`(mcs --version | sed -n "/C#\|Mono/p") 2>/dev/null`
###       CSHARPCOMPILER="";
###       if test -n "$csharp_version_raw" ; then
###         if test "$csharp_version_raw" = "$csharp_version_searched" ; then
###           CSHARPCOMPILER="mcs"
###         fi
###       fi
### 
###       # mono interpreter (ver 0.26 doesn't seem to work on Windows platforms)
###       case $host in
###       *-*-cygwin* | *-*-mingw*)
###         ;;
###       *)AC_CHECK_PROGS(CSHARPCILINTERPRETER, mint);;
###       esac
###     else 
###       if test "csc" = "$CSHARPCOMPILER"; then
###           CSHARPPATHSEPARATOR="\\\\"
###           CSHARPCYGPATH_W='cygpath -w'
###       fi
###     fi
###   fi
### else
###   CSHARPCILINTERPRETER="$CSHARPBIN"
### fi

# Cygwin requires the Windows standard (Pascal) calling convention as it is a Windows executable and not a Cygwin built executable
case $host in
*-*-cygwin* | *-*-mingw*)
    if test "$GCC" = yes; then
        CSHARPDYNAMICLINKING=" -Wl,--add-stdcall-alias"
    else
        CSHARPDYNAMICLINKING=""
    fi ;;
*)CSHARPDYNAMICLINKING="";;
esac

AC_CHECK_PROGS(GACUTIL, gacutil)

AC_SUBST(CSHARPCILINTERPRETER)
AC_SUBST(CSHARPCYGPATH_W)
AC_SUBST(CSHARPCOMPILER)
AC_SUBST(CSHARPDYNAMICLINKING)
AC_SUBST(CSHARPLIBRARYPREFIX) # Is this going to be used?
AC_SUBST(GACUTIL)

if test "X$CSHARPCOMPILER" = X; then
    enable_csharp=no 
fi
if test "X$GACUTIL" = X; then
    enable_csharp=no 
fi
AM_CONDITIONAL([CSHARP_ENABLED], [test "x$enable_csharp" = "xyes"])


# ------------
# Perl binding
# ------------

AC_ARG_ENABLE(perl, [  --disable-perl          disable the Perl binding],,
              enable_perl="yes")

if test "X$PERL" != "X"; then
  PERLINSTALLSITEARCH=`$PERL -MConfig -e 'print $Config{installsitearch};'`
  PERLMAN3DIR=`$PERL -MConfig -e 'print $Config{man3dir};'`
  PERL_CFLAGS=$($PERL -V::ccflags: | tr -d "'")
else
  PERLINSTALLSITEARCH=none
  PERLMAN3DIR=none
  PERL_CFLAGS=
fi
AC_SUBST(PERLINSTALLSITEARCH)
AC_SUBST(PERLMAN3DIR)
AC_SUBST(PERL_CFLAGS)

AC_MSG_CHECKING(for Perl API)
if test "X$enable_perl" != "Xno" ; then
  if test "X$enable_perl" != "Xyes"; then
    PERL=$enable_perl
  fi
  enable_perl=yes
fi

PERL_VERSION=`$PERL -MConfig -e 'print $Config{version}' 2>/dev/null`
if test "X$PERL_VERSION" != "X"; then
  languages_available="$languages_available perl($PERL_VERSION)"
  if test $enable_perl = yes; then
    languages="$languages perl"
  fi
fi
AM_CONDITIONAL([PERL_ENABLED],[test "x$enable_perl" = "xyes"])
AC_MSG_RESULT($enable_perl)
AC_SUBST(PERL_VERSION)


dnl Checks for zlib library (code adapted from libxml2 configure.in)
_cppflags="${CPPFLAGS}" 
_ldflags="${LDFLAGS}"

AC_ARG_WITH(zlib,
[  --with-zlib[[=DIR]]       use libz in DIR],[
  if test "$withval" != "no" -a "$withval" != "yes"; then
    Z_DIR=$withval
    CPPFLAGS="${CPPFLAGS} -I$withval/include"
    LDFLAGS="${LDFLAGS} -L$withval/lib"
  fi
]) 
saved_LIB=$LIBS
LIBS=
AC_CHECK_HEADERS(zlib.h,
    AC_SEARCH_LIBS(gzread, [z zlib1],[
        AC_DEFINE([HAVE_LIBZ], [], [Have compression library])
        if test "x${Z_DIR}" != "x"; then
            Z_CFLAGS="-I${Z_DIR}/include"
            Z_LIBS="-L${Z_DIR}/lib $LIBS"
            [case ${host} in
                *-*-solaris*)
                    Z_LIBS="-L${Z_DIR}/lib -R${Z_DIR}/lib $LIBS"
                    ;;
            esac]
        else
            Z_LIBS="$LIBS"
        fi]))
LIBS=$saved_LIB
test "z$Z_LIBS" != "z" || AC_MSG_ERROR(missing zlib)

AC_SUBST(Z_CFLAGS)
AC_SUBST(Z_LIBS)

CPPFLAGS=${_cppflags}
LDFLAGS=${_ldflags}

dnl Final step, add missing programs.
AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)


dnl API Reference documentation support
# gtkdocize greps for ^GTK_DOC_CHECK and parses it, so you need to have
# it on it's own line.
m4_ifdef([GTK_DOC_CHECK], [
GTK_DOC_CHECK([1.14],[--flavour no-tmpl])
],[
AM_CONDITIONAL([ENABLE_GTK_DOC],[false])
])

if test "z$with_html_dir" != "z" ; then
    LASSO_DOCDIR=$with_html_dir
else
    LASSO_DOCDIR='$(datadir)/doc/lasso'
fi
AC_SUBST(LASSO_DOCDIR)

AC_ARG_WITH(html-dir, [  --with-html-dir=PATH path to installed docs ])

if test "x$with_html_dir" = "x" ; then
  HTML_DIR='${datadir}/gtk-doc/html'
else
  HTML_DIR=$with_html_dir
fi
AC_SUBST(HTML_DIR)


dnl pkg-config path
AC_ARG_WITH(pkg-config, [  --with-pkg-config=PATH set pkg-config metadata search path.],
            PKG_CONFIG_PATH="${withval}", PKG_CONFIG_PATH="")
if test "z$PKG_CONFIG_PATH" != "z"; then
    export PKG_CONFIG_PATH
fi

PKG_CHECK_MODULES(LASSO, glib-2.0 >= 2.17.0 gobject-2.0 >= 2.17.0 libxml-2.0 xmlsec1 >= 1.2.6 xmlsec1-openssl >= 1.2.6 openssl)

dnl ==========================================================================
dnl Test suite (requires check)
dnl ==========================================================================
dnl Check if user disabled the tests.
AC_ARG_ENABLE(tests, [  --disable-tests         disable the test suite],,
              enable_tests="yes")
if test "x$enable_tests" = xyes ; then
  PKG_CHECK_MODULES(CHECK, check, [], [
AC_CHECK_LIB(check, srunner_set_log, enable_tests="yes", enable_tests="no")
CHECK_CFLAGS=""
CHECK_LIBS="-lcheck"
])
  AC_SUBST(CHECK_CFLAGS)
  AC_SUBST(CHECK_LIBS)
  AC_CHECK_LIB(check, srunner_set_xml, [AC_DEFINE(CHECK_IS_XML, [], [Define if check available with XML support])])
fi

AM_CONDITIONAL(WITH_TESTS, [test "x$enable_tests" = "xyes"])

AC_CHECK_PROGS(REST2HTML, rest2html rst2html)
AM_CONDITIONAL(HAVE_REST2HTML, test -n "$ac_cv_prog_REST2HTML")

AC_CHECK_PROGS(XSLTPROC, xsltproc)
AM_CONDITIONAL(HAVE_XSLTPROC, test -n "$ac_cv_prog_XSLTPROC")

AC_CHECK_PROGS(INKSCAPE, inkscape)
AM_CONDITIONAL(HAVE_INKSCAPE, test -n "$ac_cv_prog_INKSCAPE")


dnl Debug 
AC_MSG_CHECKING(for debugging) 
AC_ARG_ENABLE(debugging,   [  --enable-debugging      enable debuging optimization flags (no)])
if test "z$enable_debugging" = "zyes" ; then
    enable_debugging=yes
    LASSO_DEFINES="$LASSO_DEFINES -DLASSO_DEBUG"
    CFLAGS="$CFLAGS -O0 -g -Wall -Wextra"
else
    enable_debugging=no
fi    
AM_CONDITIONAL([DEBUGGING],[test "x$enable_debugging" = "xyes"])
AC_MSG_RESULT($enable_debugging)
AC_SUBST(DEBUGGING)

dnl Profiling 
AC_MSG_CHECKING(for profiling) 
AC_ARG_ENABLE(profiling,   [  --enable-profiling      enable profiling compilation flags (no)])
if test "z$enable_profiling" = "zyes" ; then
    AM_CFLAGS="$AM_CFLAGS -pg"
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi 

AC_ARG_WITH([default-sign-algo],
            [AS_HELP_STRING([--with-default-sign-algo=[rsa-sha1|rsa-sha256]],
                            [Default signing algorithm (rsa-sha1)]
                           )
            ]
)

SIGNING_ALGO=rsa-sha1
if test x"$with_default_sign_algo" != x; then
    if test ! "$with_default_sign_algo" = "rsa-sha1" -a ! "$with_default_sign_algo" = "rsa-sha256"; then
	AC_MSG_ERROR("Default signing algorithm must be either rsa-sha1 or rsa-sha256")
    else
	SIGNING_ALGO=$with_default_sign_algo
    fi
fi

AC_DEFINE_UNQUOTED(DEFAULT_SIGNING_ALGO, "$SIGNING_ALGO", ["The default signing algorithm"])

AC_ARG_WITH([min-hash-algo],
            [AS_HELP_STRING([--with-min-hash-algo=[sha1|sha256|sha384|sha512]],
                            [Minimal allowed hash algorithm (rsa-sha1)]
                           )
            ]
)

MIN_HASH_ALGO=sha1
if test x"$with_min_hash_algo" != x; then
    if test ! "$with_min_hash_algo" = "sha1" -a ! "$with_min_hash_algo" = "sha256" -a ! "$with_min_hash_algo" = "sha384" -a ! "$with_min_hash_algo" = "sha512"; then
	AC_MSG_ERROR("Minimal allowed hash algorithm must be one of sha1, sha256, sha384 or sha512)
    else
	MIN_HASH_ALGO=$with_min_hash_algo
    fi
fi

AC_DEFINE_UNQUOTED(MIN_HASH_ALGO, "$MIN_HASH_ALGO", ["The minimal hash algorithm"])

AC_ARG_WITH([default-key-encryption-method],
            [AS_HELP_STRING([--with-default-key-encryption-method=[rsa-pkcs1|rsa-oaep]],
                            [Default key encryption method (rsa-oaep)]
                           )
            ]
)

KEY_ENCRYPTION_METHOD=rsa-oaep
if test x"$with_default_" != x; then
    if test ! "$with_default_key_encryption_method" = "rsa-pkcs1" -a ! "$with_default_key_encryption_method" = "rsa-oaep"; then
	AC_MSG_ERROR("Default key encryption method must be either rsa-pkcs1 or rsa-oaep")
    else
	SIGNING_ALGO=$with_default_key_encryption_method
    fi
fi

AC_DEFINE_UNQUOTED(DEFAULT_KEY_ENCRYPTION_METHOD, "$KEY_ENCRYPTION_METHOD", ["The default key encryption method"])


dnl ==========================================================================
dnl Pedantic compilation
dnl ==========================================================================
AC_MSG_CHECKING(for pedantic) 
AC_ARG_ENABLE(pedantic,   [  --enable-pedantic       enable pedantic compilation flags (no)])
if test "z$enable_pedantic" = "zyes" ; then
    CFLAGS="$CFLAGS -O -pedantic -Wall -ansi -fno-inline -W -Wunused -Wimplicit -Wreturn-type -Wswitch -Wcomment -Wtrigraphs -Wformat -Wchar-subscripts -Wuninitialized -Wparentheses -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Waggregate-return -Wmissing-prototypes -Wnested-externs -Winline -Wredundant-decls"
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi    

dnl ==========================================================================
dnl Static linking
dnl ==========================================================================
LASSO_STATIC_BINARIES=""
AC_MSG_CHECKING(for static linking) 
AC_ARG_ENABLE(static_linking,   [  --enable-static-linking enable static linking (no)])
if test "z$enable_static_linking" = "zyes" ; then
    LASSO_STATIC_BINARIES="-static"
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi    
AC_SUBST(LASSO_STATIC_BINARIES)

dnl ==========================================================================
dnl Final steps: lasso config
dnl ==========================================================================
LASSO_PUB_CFLAGS="$LASSO_DEFINES"
LASSO_CORE_CFLAGS="$LASSO_CFLAGS $LASSO_DEFINES $Z_CFLAGS -DLASSO_INTERNALS" 
if test $MINGW -eq 1; then 
  LASSO_CORE_LIBS="-llasso-0"
else
  LASSO_CORE_LIBS="-llasso "
fi
AC_SUBST(LASSO_CORE_CFLAGS)
AC_SUBST(LASSO_CORE_LIBS)

LASSO_CFLAGS="$LASSO_CFLAGS"
LASSO_LIBS="-L${libdir} $Z_LIBS $LASSO_LIBS"
AC_SUBST(LASSO_CFLAGS)
AC_SUBST(LASSO_LIBS)

AC_SUBST(LASSO_PUB_CFLAGS)
AC_SUBST(LASSO_DEFINES)
AC_SUBST(LASSO_APP_DEFINES)
AC_SUBST(CFLAGS)
AC_SUBST(AM_CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)
AC_SUBST(CLASSPATH_JUNIT)
AC_SUBST(SWIG_VERSION)

dnl Dirty system often means dirty hacks...
AM_CONDITIONAL(MINGW, test $MINGW -eq 1)
AM_CONDITIONAL(DARWIN, test $DARWIN -eq 1)

dnl bindings


dnl ==========================================================================
dnl Writing result files
dnl ==========================================================================
AC_CONFIG_FILES([lasso-src-config], [chmod +x lasso-src-config])
AC_OUTPUT(
[Makefile
docs/Makefile
docs/lasso-book/Makefile
docs/lasso-book/figures/Makefile
docs/reference/Makefile
docs/reference/lasso/version.xml
docs/reference/lasso/Makefile
lasso/Makefile
lasso/id-ff/Makefile
lasso/saml-2.0/Makefile
lasso/xml/Makefile
lasso/xml/ecp/Makefile
lasso/xml/saml-2.0/Makefile
lasso/xml/soap-1.1/Makefile
lasso/xml/dsig/Makefile
tests/Makefile
tests/data/Makefile
lasso.pc
bindings/Makefile
bindings/java/Makefile
bindings/python/Makefile
bindings/python/tests/Makefile
bindings/php5/Makefile
bindings/php5/examples/Makefile
bindings/php5/tests/Makefile
bindings/php7/Makefile
bindings/php7/examples/Makefile
bindings/php7/tests/Makefile
bindings/perl/Makefile
])

languages_available=`echo $languages_available | sed -e "s/^ //" `
AC_MSG_RESULT(

=============
Configuration
=============

Main
----

Compiler:                ${CC} 
CFLAGS:                  ${AM_CFLAGS} ${CFLAGS}
Install prefix:          ${prefix}
Debugging:               $enable_debugging

Optionals builds
----------------
  
Available languages:    ${languages_available}

Java binding:           ${enable_java}
Perl binding:           ${enable_perl}
PHP 5 binding:          ${enable_php5}
PHP 7 binding:          ${enable_php7}
Python binding:         ${enable_python}

C API references:       ${enable_gtk_doc}
Tests suite:            ${enable_tests}

Crypto settings
---------------
Default signature:      ${SIGNING_ALGO}
Minimal accepted hash:  ${MIN_HASH_ALGO}
Key encryption method:  ${KEY_ENCRYPTION_METHOD}
)
