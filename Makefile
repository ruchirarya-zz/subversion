#
# Makefile.in:  template Makefile for Subversion
#
# ====================================================================
#    Licensed to the Apache Software Foundation (ASF) under one
#    or more contributor license agreements.  See the NOTICE file
#    distributed with this work for additional information
#    regarding copyright ownership.  The ASF licenses this file
#    to you under the Apache License, Version 2.0 (the
#    "License"); you may not use this file except in compliance
#    with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing,
#    software distributed under the License is distributed on an
#    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#    KIND, either express or implied.  See the License for the
#    specific language governing permissions and limitations
#    under the License.
# ====================================================================
#

top_builddir = .
top_srcdir = ..
abs_builddir = /home/arya/Desktop/njgitsvn/objcode
abs_srcdir = /home/arya/Desktop/njgitsvn/objcode/..
VPATH = ..

SVN_RA_LIB_DEPS = $(RA_LOCAL_DEPS) $(RA_SVN_DEPS) $(RA_SERF_DEPS)
SVN_RA_LIB_INSTALL_DEPS = install-ramod-lib install-serf-lib
SVN_RA_LIB_LINK = $(RA_LOCAL_LINK) $(RA_SVN_LINK) $(RA_SERF_LINK)

SVN_FS_LIB_DEPS = $(FS_FS_DEPS) $(FS_X_DEPS)
SVN_FS_LIB_INSTALL_DEPS = install-fsmod-lib
SVN_FS_LIB_LINK = $(FS_FS_LINK) $(FS_X_LINK)

SWIG_SRC_DIR = $(abs_srcdir)/subversion/bindings/swig
SWIG_BUILD_DIR = $(abs_builddir)/subversion/bindings/swig

SCHEMA_DIR = subversion/svn/schema

SVN_APR_LIBS = -L/usr/local/apr/lib -lapr-1
SVN_APRUTIL_LIBS = -L/usr/local/apr/lib -laprutil-1      -lexpat
SVN_APR_MEMCACHE_LIBS = 
SVN_DB_LIBS = 
SVN_GPG_AGENT_LIBS = @SVN_GPG_AGENT_LIBS@
SVN_GNOME_KEYRING_LIBS = 
SVN_KWALLET_LIBS = 
SVN_MAGIC_LIBS = 
SVN_INTL_LIBS = 
SVN_SASL_LIBS = 
SVN_SERF_LIBS = -lserf-1  
SVN_SQLITE_LIBS = -lsqlite3
SVN_XML_LIBS = 
SVN_ZLIB_LIBS = -lz
SVN_SSL_LIBS = -L/usr/local/ssl/lib -lssl -lcrypto

LIBS = 

prefix = /usr/local
exec_prefix = ${prefix}
libdir = ${exec_prefix}/lib
fsmod_libdir = ${exec_prefix}/lib
ramod_libdir = ${exec_prefix}/lib
bdb_libdir = ${exec_prefix}/lib
gnome_keyring_libdir = ${exec_prefix}/lib
gpg_agent_libdir = ${exec_prefix}/lib
kwallet_libdir = ${exec_prefix}/lib
serf_libdir = ${exec_prefix}/lib
bindir = ${exec_prefix}/bin
includedir = ${prefix}/include
mandir = ${datarootdir}/man
srcdir = ..
canonicalized_srcdir = ../
datadir = ${datarootdir}
datarootdir = ${prefix}/share
localedir = ${datadir}/locale

# where to install libsvn_swig_*
swig_py_libdir = ${exec_prefix}/lib
swig_pl_libdir = ${exec_prefix}/lib
swig_rb_libdir = ${exec_prefix}/lib

### these possibly need further discussion
swig_pydir = ${exec_prefix}/lib/svn-python/libsvn
swig_pydir_extra = ${exec_prefix}/lib/svn-python/svn
swig_pldir = ${exec_prefix}/lib/svn-perl
swig_rbdir = $(SWIG_RB_SITE_ARCH_DIR)/svn/ext
toolsdir = ${exec_prefix}/bin/svn-tools

# where to install pkg-config files
pkgconfig_dir = $(datadir)/pkgconfig

javahl_javadir = ${exec_prefix}/lib/svn-javahl
javahl_javahdir = ${exec_prefix}/lib/svn-javahl/include
javahl_libdir = ${exec_prefix}/lib
javahl_test_rootdir=$(abs_builddir)/subversion/bindings/javahl/test-work
javahl_test_srcdir=$(abs_srcdir)/subversion/bindings/javahl

gnome_auth_dir = $(abs_builddir)/subversion/libsvn_auth_gnome_keyring/.libs
kwallet_auth_dir = $(abs_builddir)/subversion/libsvn_auth_kwallet/.libs
auth_plugin_dirs = $(gnome_auth_dir):$(kwallet_auth_dir)

MSGFMT = /usr/bin/msgfmt
MSGFMTFLAGS = -c
MSGMERGE = /usr/bin/msgmerge
XGETTEXT = /usr/bin/xgettext
TRANG = none

PACKAGE_NAME=subversion
PACKAGE_VERSION=1.9.2

CC = gcc
CXX = g++
CPP = gcc -E
EXEEXT = 

SHELL = /bin/bash
LIBTOOL = $(SHELL) "/home/arya/Desktop/njgitsvn/objcode/libtool"
LTFLAGS = --tag=CC --silent
LTCXXFLAGS = --tag=CXX --silent
LT_CFLAGS = -static 
LT_LDFLAGS = -static 
LT_SO_VERSION = -version-info 0
LT_NO_UNDEFINED = 
LT_CXX_LIBADD = 

INCLUDES = -I$(top_srcdir)/subversion/include -I$(top_builddir)/subversion \
            -I/usr/local/apr/include/apr-1   -I/usr/local/apr/include/apr-1 -I/usr/local/ssl/include   \
             -I/usr/local/ssl/include/openssl \
             \
            -I/usr/local/include/serf-1    \
            -I/usr/local/lib/include

APACHE_INCLUDES = 
APACHE_LIBEXECDIR = $(DESTDIR)no
APACHE_LDFLAGS = 

SVN_USE_GMOCK = false
GMOCK_INCLUDES = -I/home/arya/Desktop/njgitsvn/subversion-1.9.2/gmock-fused

SWIG = none
SWIG_PY_INCLUDES = $(SWIG_INCLUDES) -I/usr/include/python2.7 -I$(SWIG_SRC_DIR)/python/libsvn_swig_py
SWIG_PY_COMPILE = x86_64-linux-gnu-gcc -pthread -fPIC -g3 -fno-omit-frame-pointer -fno-inline -Wall -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations -pg -pthread   -DSVN_DEBUG -DAP_DEBUG -L/usr/local/ssl/lib -lssl -lcrypto
SWIG_PY_LINK = x86_64-linux-gnu-gcc -pthread -shared -Wl,-O1 -Wl,-Bsymbolic-functions -Wl,-Bsymbolic-functions -Wl,-z,relro -fno-strict-aliasing -DNDEBUG -g -fwrapv -O2 -Wall -Wstrict-prototypes -D_FORTIFY_SOURCE=2 -g -fstack-protector --param=ssp-buffer-size=4 -Wformat -Werror=format-security
SWIG_PY_LIBS = -Wl,-O1 -Wl,-Bsymbolic-functions -Wl,-Bsymbolic-functions -Wl,-z,relro
SWIG_PL_INCLUDES = $(SWIG_INCLUDES)  -D_REENTRANT -D_GNU_SOURCE -DDEBIAN -fstack-protector -fno-strict-aliasing -pipe -I/usr/local/include -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64  -I/usr/lib/perl/5.18/CORE 
SWIG_RB_INCLUDES =  -I$(SWIG_SRC_DIR)/ruby/libsvn_swig_ruby
SWIG_RB_COMPILE = none
SWIG_RB_LINK = none
SWIG_RB_LIBS = 
SWIG_RB_SITE_LIB_DIR = 
SWIG_RB_SITE_ARCH_DIR = 
SWIG_RB_TEST_VERBOSE = 
SWIG_RB_RI_DATADIR = $(DESTDIR)$(datadir)/ri/$(RUBY_MAJOR).$(RUBY_MINOR)/site

CTYPESGEN = none
CTYPES_PYTHON_SRC_DIR = $(abs_srcdir)/subversion/bindings/ctypes-python

JAVAHL_JAR=subversion/bindings/javahl/svn-javahl.jar
JAVAHL_INCLUDES= none -I$(abs_builddir)/subversion/bindings/javahl/include

CXXHL_INCLUDES = -I$(abs_srcdir)/subversion/bindings/cxxhl/include

SVN_APR_CONFIG = /usr/local/apr/bin/apr-1-config
SVN_APR_INCLUDES =  -I/usr/local/apr/include/apr-1 
SVN_APRUTIL_CONFIG = /usr/local/apr/bin/apu-1-config
SVN_APRUTIL_INCLUDES =  -I/usr/local/apr/include/apr-1 -I/usr/local/ssl/include 
SVN_SSL_INCLUDES = -I/usr/local/ssl/include

MKDIR = /usr/bin/install -c -d

DOXYGEN = none

# The EXTRA_ parameters can be used to pass extra flags at 'make' time.
CFLAGS = -g3 -fno-omit-frame-pointer -fno-inline -Wall -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations -pg -pthread   -DSVN_DEBUG -DAP_DEBUG  $(EXTRA_CFLAGS) -I/usr/local/ssl/include -I/usr/local/ssl/include/openssl -I/usr/local/lib/include -L/usr/local/ssl/lib -lssl -lcrypto
CMODEFLAGS = -std=c90 
CSSLFLAGS = -lssl -lcrypto
CNOWARNFLAGS = -w 
CMAINTAINERFLAGS = -Wall -Wpointer-arith -Wwrite-strings -Wshadow -Wformat=2 -Wunused -Waggregate-return -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wno-multichar -Wredundant-decls -Wnested-externs -Winline -Wno-long-long -Wbad-function-cast -Wno-format-nonliteral -Wno-system-headers -Wold-style-definition -Werror=declaration-after-statement -Werror=implicit-function-declaration 
CXXFLAGS = -g3 -fno-omit-frame-pointer -fno-inline   -DSVN_DEBUG -DAP_DEBUG  $(EXTRA_CXXFLAGS)
CXXMODEFLAGS = -std=c++98 
CXXNOWARNFLAGS = -w 
CXXMAINTAINERFLAGS = -Wall -Wpointer-arith -Wwrite-strings -Wshadow -Wunused -Wunreachable-code -Wno-system-headers 
### A few of the CFLAGS (e.g. -Wmissing-prototypes, -Wstrict-prototypes,
### -Wmissing-declarations) are not valid for C++, and should be somehow
### suppressed (but they may come from httpd or APR).
CPPFLAGS =   -D_REENTRANT -D_GNU_SOURCE -DAPR_POOL_DEBUG=1 $(EXTRA_CPPFLAGS)
LDFLAGS =   -L/usr/local/ssl/lib -lssl -lcrypto -L/usr/local/lib    -L/usr/local/lib/lib $(EXTRA_LDFLAGS)
SWIG_LDFLAGS =  $(EXTRA_SWIG_LDFLAGS)
SWIG_CPPFLAGS =   -D_REENTRANT -D_GNU_SOURCE -DAPR_POOL_DEBUG=1 $(EXTRA_CPPFLAGS)

COMPILE = $(CC) $(CMODEFLAGS) $(CPPFLAGS) $(CMAINTAINERFLAGS) $(CFLAGS) $(INCLUDES)
COMPILE_NOWARN = $(CC) $(CMODEFLAGS) $(CPPFLAGS) $(CNOWARNFLAGS) $(CFLAGS) $(INCLUDES)
COMPILE_CXX = $(CXX) $(CXXMODEFLAGS) $(CPPFLAGS) $(CXXMAINTAINERFLAGS) $(CXXFLAGS) $(INCLUDES)
COMPILE_CXX_NOWARN = $(CXX) $(CXXMODEFLAGS) $(CPPFLAGS) $(CXXNOWARNFLAGS) $(CXXFLAGS) $(INCLUDES)
LT_COMPILE = $(LIBTOOL) $(LTFLAGS) --mode=compile $(COMPILE) $(LT_CFLAGS)
LT_COMPILE_CXX = $(LIBTOOL) $(LTCXXFLAGS) --mode=compile $(COMPILE_CXX) $(LT_CFLAGS)
LT_COMPILE_CXX_NOWARN = $(LIBTOOL) $(LTCXXFLAGS) --mode=compile $(COMPILE_CXX_NOWARN) $(LT_CFLAGS)
# Execute a command that loads libraries from the build dir
LT_EXECUTE = $(LIBTOOL) $(LTFLAGS) --mode=execute `for f in $(abs_builddir)/subversion/*/*.la; do echo -dlopen $$f; done`

# special compilation for files destined for mod_dav_svn
COMPILE_APACHE_MOD = $(LIBTOOL) $(LTFLAGS) --mode=compile $(CC) $(CMODEFLAGS) $(CPPFLAGS) $(CFLAGS) $(CMAINTAINERFLAGS) $(LT_CFLAGS) $(APACHE_INCLUDES) $(INCLUDES) -o $@ -c

# special compilation for files destined for libsvn_swig_* (e.g. swigutil_*.c)
COMPILE_SWIG_PY = $(LIBTOOL) $(LTFLAGS) --mode=compile $(SWIG_PY_COMPILE) $(CPPFLAGS) $(LT_CFLAGS) -DSWIGPYTHON $(SWIG_PY_INCLUDES) $(INCLUDES) -o $@ -c
COMPILE_SWIG_PL = $(LIBTOOL) $(LTFLAGS) --mode=compile $(CC) $(CPPFLAGS) $(CFLAGS) $(LT_CFLAGS) $(SWIG_PL_INCLUDES) $(INCLUDES) -o $@ -c
COMPILE_SWIG_RB = $(LIBTOOL) $(LTFLAGS) --mode=compile $(SWIG_RB_COMPILE) $(CPPFLAGS) $(LT_CFLAGS) $(SWIG_RB_INCLUDES) $(INCLUDES) -o $@ -c

# special compilation for files destined for javahl (i.e. C++)
COMPILE_JAVAHL_CXX = $(LIBTOOL) $(LTCXXFLAGS) --mode=compile $(COMPILE_CXX) $(LT_CFLAGS) $(JAVAHL_INCLUDES) -o $@ -c
COMPILE_JAVAHL_JAVAC = $(JAVAC) $(JAVAC_FLAGS)
COMPILE_JAVAHL_JAVAH = $(JAVAH)
COMPILE_JAVAHL_COMPAT_JAVAC = $(JAVAC) $(JAVAC_COMPAT_FLAGS)

# On Mac OS X, export an env variable so that the tests can run without
# being installed. OS X needs the DYLD_LIBRARY_PATH env variable set in
# order to find the libraries to link against, because we can't effectively
# use rpath due to way rpath is implemented in the Mach executable format.
TEST_SHLIB_VAR_JAVAHL=\
  if [ "LD_LIBRARY_PATH" = "DYLD_LIBRARY_PATH" ]; then \
    for d in $(abs_builddir)/subversion/libsvn_*; do \
      if [ -n "$$DYLD_LIBRARY_PATH" ]; then \
        LD_LIBRARY_PATH="$$LD_LIBRARY_PATH:$$d/.libs"; \
      else \
        LD_LIBRARY_PATH="$$d/.libs"; \
      fi; \
    done; \
    export LD_LIBRARY_PATH; \
  fi;
TEST_SHLIB_VAR_SWIG_PY=\
  if [ "LD_LIBRARY_PATH" = "DYLD_LIBRARY_PATH" ]; then \
    for d in $(SWIG_PY_DIR)/libsvn_swig_py $(SWIG_PY_DIR)/../../../libsvn_*; do \
      if [ -n "$$DYLD_LIBRARY_PATH" ]; then \
        LD_LIBRARY_PATH="$$LD_LIBRARY_PATH:$$d/.libs"; \
      else \
        LD_LIBRARY_PATH="$$d/.libs"; \
      fi; \
    done; \
    export LD_LIBRARY_PATH; \
  fi;
TEST_SHLIB_VAR_SWIG_RB=\
  if [ "LD_LIBRARY_PATH" = "DYLD_LIBRARY_PATH" ]; then \
    for d in $(SWIG_RB_DIR)/libsvn_swig_ruby $(SWIG_RB_DIR)/../../../libsvn_*; do \
      if [ -n "$$DYLD_LIBRARY_PATH" ]; then \
        LD_LIBRARY_PATH="$$LD_LIBRARY_PATH:$$d/.libs"; \
      else \
        LD_LIBRARY_PATH="$$d/.libs"; \
      fi; \
    done; \
    export LD_LIBRARY_PATH; \
  fi;

# special compilation for files destined for cxxhl
COMPILE_CXXHL_CXX = $(LT_COMPILE_CXX) $(CXXHL_INCLUDES) -o $@ -c
COMPILE_GMOCK_CXX = $(LT_COMPILE_CXX_NOWARN) $(GMOCK_INCLUDES) -o $@ -c
COMPILE_CXXHL_GMOCK_CXX = $(LT_COMPILE_CXX) $(CXXHL_INCLUDES) $(GMOCK_INCLUDES) -o $@ -c

LINK = $(LIBTOOL) $(LTFLAGS) --mode=link $(CC) $(LT_LDFLAGS) $(CFLAGS) $(LDFLAGS) -rpath $(libdir)
LINK_LIB = $(LINK) $(LT_SO_VERSION)
LINK_CXX = $(LIBTOOL) $(LTCXXFLAGS) --mode=link $(CXX) $(LT_LDFLAGS) $(CXXFLAGS) $(LDFLAGS) -rpath $(libdir)
LINK_CXX_LIB = $(LINK_CXX) $(LT_SO_VERSION)

# special link rule for mod_dav_svn
LINK_APACHE_MOD = $(LIBTOOL) $(LTFLAGS) --mode=link $(CC) $(LT_LDFLAGS) $(CFLAGS) $(LDFLAGS) -rpath $(APACHE_LIBEXECDIR) -avoid-version -module $(APACHE_LDFLAGS)

# Special LDFLAGS for some libraries
libsvn_auth_gnome_keyring_LDFLAGS = -Wl,--no-undefined
libsvn_auth_kwallet_LDFLAGS = -Wl,--no-undefined
libsvn_client_LDFLAGS = -Wl,--no-undefined
libsvn_delta_LDFLAGS = -Wl,--no-undefined
libsvn_diff_LDFLAGS = -Wl,--no-undefined
libsvn_fs_LDFLAGS = -Wl,--no-undefined
libsvn_fs_base_LDFLAGS = -Wl,--no-undefined
libsvn_fs_fs_LDFLAGS = -Wl,--no-undefined
libsvn_fs_util_LDFLAGS = -Wl,--no-undefined
libsvn_ra_LDFLAGS = -Wl,--no-undefined
libsvn_ra_local_LDFLAGS = -Wl,--no-undefined
libsvn_ra_serf_LDFLAGS = -Wl,--no-undefined
libsvn_ra_svn_LDFLAGS = -Wl,--no-undefined
libsvn_repos_LDFLAGS = -Wl,--no-undefined
libsvn_subr_LDFLAGS = -Wl,--no-undefined
libsvn_wc_LDFLAGS = -Wl,--no-undefined

# Compilation of SWIG-generated C source code
COMPILE_PY_WRAPPER = $(LIBTOOL) $(LTFLAGS) --mode=compile $(SWIG_PY_COMPILE) $(LT_CFLAGS) $(CPPFLAGS) $(SWIG_PY_INCLUDES) -prefer-pic -c -o $@
COMPILE_RB_WRAPPER = $(LIBTOOL) $(LTFLAGS) --mode=compile $(SWIG_RB_COMPILE) $(LT_CFLAGS) $(CPPFLAGS) $(SWIG_RB_INCLUDES) -prefer-pic -c -o $@

# these commands link the wrapper objects into an extension library/module
LINK_PY_WRAPPER = $(LIBTOOL) $(LTFLAGS) --mode=link $(SWIG_PY_LINK) $(SWIG_LDFLAGS) -rpath $(swig_pydir) -avoid-version -module
LINK_RB_WRAPPER = $(LIBTOOL) $(LTFLAGS) --mode=link $(SWIG_RB_LINK) $(SWIG_LDFLAGS) -rpath $(swig_rbdir) -avoid-version -module

LINK_JAVAHL_CXX = $(LIBTOOL) $(LTCXXFLAGS) --mode=link $(CXX) $(LT_LDFLAGS) $(CXXFLAGS) $(LDFLAGS) $(LT_CXX_LIBADD) -rpath $(libdir)

INSTALL = /usr/bin/install -c
INSTALL_LIB = $(LIBTOOL) --mode=install $(INSTALL)
INSTALL_FSMOD_LIB = $(INSTALL_LIB)
INSTALL_RAMOD_LIB = $(INSTALL_LIB)
INSTALL_APR_MEMCACHE_LIB = $(INSTALL_LIB)
INSTALL_BDB_LIB = $(INSTALL_LIB)
INSTALL_GPG_AGENT_LIB = $(INSTALL_LIB)
INSTALL_GNOME_KEYRING_LIB = $(INSTALL_LIB)
INSTALL_KWALLET_LIB = $(INSTALL_LIB)
INSTALL_SERF_LIB = $(INSTALL_LIB)
INSTALL_BIN = $(LIBTOOL) --mode=install $(INSTALL)
INSTALL_CONTRIB = $(LIBTOOL) --mode=install $(INSTALL)
INSTALL_TOOLS = $(LIBTOOL) --mode=install $(INSTALL)
INSTALL_INCLUDE = $(INSTALL) -m 644
INSTALL_MOD_SHARED =  -i -S LIBEXECDIR="$(APACHE_LIBEXECDIR)" 
INSTALL_DATA = $(INSTALL) -m 644
INSTALL_LOCALE = $(INSTALL_DATA)
INSTALL_APACHE_MODS = false

### this isn't correct yet
INSTALL_SWIG_PY = $(INSTALL_LIB)
INSTALL_SWIG_PY_LIB = $(INSTALL_LIB)
INSTALL_SWIG_PL_LIB = $(INSTALL_LIB)
INSTALL_SWIG_RB = $(INSTALL_LIB)
INSTALL_SWIG_RB_LIB = $(INSTALL_LIB)

INSTALL_JAVAHL_LIB = $(INSTALL_LIB)

# additional installation rules for the SWIG wrappers
INSTALL_EXTRA_SWIG_PY=\
  $(MKDIR) $(DESTDIR)$(swig_pydir); \
  $(MKDIR) $(DESTDIR)$(swig_pydir_extra); \
  for i in $(abs_srcdir)/subversion/bindings/swig/python/svn/*.py; do \
    $(INSTALL_DATA) "$$i" $(DESTDIR)$(swig_pydir_extra); \
  done; \
  for i in $(abs_srcdir)/subversion/bindings/swig/python/*.py; do \
    $(INSTALL_DATA) "$$i" $(DESTDIR)$(swig_pydir); \
  done; \
  if test "$(abs_srcdir)" != "$(abs_builddir)"; then \
    for i in $(abs_builddir)/subversion/bindings/swig/python/*.py; do \
      $(INSTALL_DATA) "$$i" $(DESTDIR)$(swig_pydir); \
    done; \
  fi; \
  $(PYTHON) -c 'import compileall; \
    compileall.compile_dir("$(DESTDIR)$(swig_pydir)", 1, "$(swig_pydir)"); \
    compileall.compile_dir("$(DESTDIR)$(swig_pydir_extra)", 1, \
    "$(swig_pydir_extra)");'

# The path to generated and complementary source files for the SWIG
# bindings.
SWIG_PL_DIR = $(abs_builddir)/subversion/bindings/swig/perl
SWIG_PY_DIR = $(abs_builddir)/subversion/bindings/swig/python
SWIG_RB_DIR = $(abs_builddir)/subversion/bindings/swig/ruby

# The path to the source files for the SWIG bindings
SWIG_PL_SRC_DIR = $(abs_srcdir)/subversion/bindings/swig/perl
SWIG_PY_SRC_DIR = $(abs_srcdir)/subversion/bindings/swig/python
SWIG_RB_SRC_DIR = $(abs_srcdir)/subversion/bindings/swig/ruby

### Automate JAR creation using Makefile generator's javahl-java.jar
### property.  Enhance generator to support JAR installation.
JAVAHL_MANIFEST_IN = $(abs_srcdir)/subversion/bindings/javahl/Manifest.in
JAVAHL_MANIFEST = subversion/bindings/javahl/Manifest
INSTALL_EXTRA_JAVAHL_JAVA=\
	sed s/%bundleVersion/$(PACKAGE_VERSION)/ $(JAVAHL_MANIFEST_IN) > $(JAVAHL_MANIFEST); \
	$(JAR) cfm $(JAVAHL_JAR) $(JAVAHL_MANIFEST) -C subversion/bindings/javahl/classes org; \
	$(INSTALL_DATA) $(JAVAHL_JAR) $(DESTDIR)$(javahl_javadir);

INSTALL_EXTRA_JAVAHL_LIB=

INSTALL_EXTRA_SWIG_RB=\
  @echo $(MKDIR) $(DESTDIR)$(SWIG_RB_SITE_LIB_DIR)/svn; \
  $(MKDIR) $(DESTDIR)$(SWIG_RB_SITE_LIB_DIR)/svn; \
  for i in $(abs_srcdir)/subversion/bindings/swig/ruby/svn/*.rb; do \
    echo $(INSTALL_DATA) "$$i" $(DESTDIR)$(SWIG_RB_SITE_LIB_DIR)/svn; \
    $(INSTALL_DATA) "$$i" $(DESTDIR)$(SWIG_RB_SITE_LIB_DIR)/svn; \
  done

APXS = 
HTTPD_VERSION = 

PYTHON = /usr/bin/python
PERL = /usr/bin/perl

JDK = /usr
JAVA = 
JAVAC = none
JAVADOC = none
JAVAC_FLAGS = 
JAVAC_COMPAT_FLAGS = 
JAVAH = none
JAR = none

JAVA_CLASSPATH=$(abs_srcdir)/subversion/bindings/javahl/src:
javahl_java_CLASSPATH=$(JAVA_CLASSPATH)
javahl_compat_CLASSPATH=$(JAVA_CLASSPATH)
javahl_tests_CLASSPATH=$(JAVA_CLASSPATH)
javahl_compat_tests_CLASSPATH=$(JAVA_CLASSPATH)

RUBY = none
RUBY_MAJOR = 
RUBY_MINOR = 
RDOC = 

ECHO_C = 
ECHO_N = -n

TESTS = $(TEST_PROGRAMS) 

all: mkdir-init local-all
clean: local-clean
distclean: local-distclean
extraclean: local-extraclean
install: local-install revision-install

include $(top_srcdir)/build-outputs.mk

local-all: fsmod-lib ramod-lib lib bin test sub-test  tools serf-lib locale 

transform-libtool-scripts: fsmod-lib ramod-lib lib bin test sub-test  tools serf-lib locale
	@$(SHELL) $(top_srcdir)/build/transform_libtool_scripts.sh

locale-gnu-pot:
	cd $(abs_srcdir) && XGETTEXT="$(XGETTEXT)" MSGMERGE="$(MSGMERGE)" \
	  $(SHELL) tools/po/po-update.sh pot

# "make locale-gnu-po-update" updates all translations.
# "make locale-gnu-po-update PO=ll" updates only the ll.po file.
locale-gnu-po-update:
	cd $(abs_srcdir) && XGETTEXT="$(XGETTEXT)" MSGMERGE="$(MSGMERGE)" \
	  $(SHELL) tools/po/po-update.sh $(PO)

# clean everything but the bulky test output, returning the system back
# to before 'make' was run.
fast-clean: doc-clean
	@list='$(BUILD_DIRS)'; for i in $$list; do                   \
          if [ -d $$i ]; then                                        \
            (cd $$i && rm -f *.o *.lo *.la *.la-a *.spo *.mo &&      \
             rm -rf .libs);                                          \
          fi                                                         \
        done
	echo $(CLEAN_FILES) | xargs rm -f --
	find $(CTYPES_PYTHON_SRC_DIR) $(SWIG_PY_SRC_DIR) $(SWIG_PY_DIR) \
		$(abs_srcdir)/build $(top_srcdir)/subversion/tests/cmdline/svntest \
		-name "*.pyc" -exec rm {} ';'

# clean everything, returning to before './configure' was run.
SVN_CONFIG_SCRIPT_FILES =  tools/backup/hot-backup.py tools/hook-scripts/commit-access-control.pl subversion/bindings/swig/perl/native/Makefile.PL
local-distclean: local-clean
	rm -fr config.cache config.log config.nice config.status \
	  libtool mkmf.log subversion/svn_private_config.h \
	  subversion/bindings/javahl/classes \
	  subversion/bindings/javahl/include \
	  subversion/libsvn_*/*.pc \
	$(SVN_CONFIG_SCRIPT_FILES)
	rm -f Makefile

# clean everything out, returning to before './autogen.sh' was run.
local-extraclean: extraclean-bindings local-distclean
	rm -f $(top_srcdir)/build-outputs.mk \
              $(top_srcdir)/subversion/svn_private_config.h.in \
              $(top_srcdir)/configure \
              $(top_srcdir)/gen-make.opts \
              $(top_srcdir)/build/config.guess \
              $(top_srcdir)/build/config.sub \
              $(top_srcdir)/build/libtool.m4 \
              $(top_srcdir)/build/ltoptions.m4 \
              $(top_srcdir)/build/ltsugar.m4 \
              $(top_srcdir)/build/ltversion.m4 \
              $(top_srcdir)/build/lt~obsolete.m4 \
              $(top_srcdir)/build/ltmain.sh \
              $(top_srcdir)/build/transform_libtool_scripts.sh \
              $(EXTRACLEAN_FILES)


# clean everything, including test output.
local-clean: check-clean clean-bindings fast-clean

local-install: install-fsmod-lib install-ramod-lib install-serf-lib install-lib install-include install-static install-locale

revision-install:
	test -d $(DESTDIR)$(includedir)/subversion-1 || \
	  $(MKDIR) $(DESTDIR)$(includedir)/subversion-1
	(subversion/svnversion/svnversion $(top_srcdir) 2> /dev/null ||  \
	 svnversion $(top_srcdir) 2> /dev/null ||                        \
	 echo "unknown";                                                 \
	) > $(DESTDIR)$(includedir)/subversion-1/svn-revision.txt

install-static: install-bin install-docs install-serf-lib

# JavaHL target aliases
javahl: mkdir-init javahl-java javahl-javah javahl-callback-javah javahl-remote-javah javahl-types-javah javahl-util-javah javahl-lib  javahl-compat
install-javahl: javahl install-javahl-java install-javahl-javah install-javahl-lib
javahl-compat: javahl-compat-java 

clean-javahl:
	if [ -d $(javahl_test_rootdir) ]; then \
	  rm -rf $(javahl_test_rootdir)/*;     \
	fi
	rm -rf $(javahl_java_PATH) $(javahl_javah_PATH) 
	rm -f $(libsvnjavahl_PATH)/*.la $(JAVAHL_JAR)
	rm -f $(libsvnjavahl_PATH)/*.lo
	rm -f $(libsvnjavahl_PATH)/*.o

check-tigris-javahl: javahl-compat
	
	$(TEST_SHLIB_VAR_JAVAHL) \
	$(JAVA) -Xcheck:jni "-Dtest.rootdir=$(javahl_test_rootdir)" "-Dtest.srcdir=$(javahl_test_srcdir)" "-Dtest.rooturl=$(BASE_URL)" "-Dtest.fstype=$(FS_TYPE)" "-Djava.library.path=:$(libdir)" -classpath "$(javahl_compat_tests_PATH):$(javahl_tests_CLASSPATH)" "-Dtest.tests=$(JAVAHL_TESTS)" org.tigris.subversion.javahl.RunTests

check-apache-javahl: javahl
	
	$(TEST_SHLIB_VAR_JAVAHL) \
	$(JAVA) -Xcheck:jni "-Dtest.rootdir=$(javahl_test_rootdir)" "-Dtest.srcdir=$(javahl_test_srcdir)" "-Dtest.rooturl=$(BASE_URL)" "-Dtest.fstype=$(FS_TYPE)" "-Djava.library.path=:$(libdir)" -classpath "$(javahl_tests_PATH):$(javahl_tests_CLASSPATH)" "-Dtest.tests=$(JAVAHL_TESTS)" org.apache.subversion.javahl.RunTests

check-deprecated-authn-javahl: javahl
	
	$(TEST_SHLIB_VAR_JAVAHL) \
	$(JAVA) -Xcheck:jni "-Dtest.rootdir=$(javahl_test_rootdir)" "-Dtest.srcdir=$(javahl_test_srcdir)" "-Dtest.rooturl=$(BASE_URL)" "-Dtest.fstype=$(FS_TYPE)" "-Djava.library.path=:$(libdir)" -classpath "$(javahl_tests_PATH):$(javahl_tests_CLASSPATH)" "-Dtest.tests=$(JAVAHL_TESTS)" "-Dtest.authn.deprecated=true" org.apache.subversion.javahl.RunTests

check-javahl: check-apache-javahl

check-all-javahl: check-apache-javahl check-tigris-javahl check-deprecated-authn-javahl

# "make check CLEANUP=true" will clean up directories for successful tests.
# "make check TESTS=subversion/tests/cmdline/basic_tests.py"
#  will perform only basic tests (likewise for other tests).
check: bin  $(TEST_DEPS) 
	@if test "$(PYTHON)" != "none"; then                                 \
	  if test "$(CLEANUP)" != ""; then                                   \
	    flags="--cleanup $$flags";                                       \
	  fi;                                                                \
	  if test "$(BASE_URL)" != ""; then                                  \
	    flags="--url $(BASE_URL) $$flags";                               \
	  fi;                                                                \
	  if test "$(SKIP_C_TESTS)" != ""; then                              \
	    flags="--skip-c-tests $$flags";                                  \
	  fi;                                                                \
	  if test "$(DUMP_LOAD_CROSS_CHECK)" != ""; then                     \
	    flags="--dump-load-cross-check $$flags";                         \
	  fi;                                                                \
	  if test "$(FS_TYPE)" != ""; then                                   \
	    flags="--fs-type $(FS_TYPE) $$flags";                            \
	  fi;                                                                \
	  if test "$(HTTP_LIBRARY)" != ""; then                              \
	    flags="--http-library $(HTTP_LIBRARY) $$flags";                  \
	  fi;                                                                \
	  if test "$(HTTPD_VERSION)" != ""; then                             \
	     flags="--httpd-version $(HTTPD_VERSION) $$flags";               \
	  fi;                                                                \
	  if test "$(SERVER_MINOR_VERSION)" != ""; then                      \
	    flags="--server-minor-version $(SERVER_MINOR_VERSION) $$flags";  \
	  fi;                                                                \
	  if test "$(ENABLE_SASL)" != ""; then                               \
	    flags="--enable-sasl $$flags";                                   \
	  fi;                                                                \
	  if test "$(FSFS_SHARDING)" != ""; then                             \
	    flags="--fsfs-sharding $(FSFS_SHARDING) $$flags";                \
	  fi;                                                                \
	  if test "$(FSFS_PACKING)" != ""; then                              \
	    flags="--fsfs-packing $$flags";                                  \
	  fi;                                                                \
	  if test "$(PARALLEL)" != ""; then                                  \
	    flags="--parallel $(PARALLEL) $$flags";                          \
	  fi;                                                                \
	  if test "$(LOG_TO_STDOUT)" != ""; then                             \
	    flags="--log-to-stdout $$flags";                                 \
	  fi;                                                                \
	  if test "$(MILESTONE_FILTER)" != ""; then                          \
	    flags="--list --milestone-filter=$(MILESTONE_FILTER)             \
		   --mode-filter=$(MODE_FILTER) --log-to-stdout $$flags";    \
	  fi;                                                                \
	  if test "$(SET_LOG_LEVEL)" != ""; then                             \
	    flags="--set-log-level $(SET_LOG_LEVEL) $$flags";                \
	  fi;                                                                \
	  if test "$(SSL_CERT)" != ""; then                                  \
	    flags="--ssl-cert $(SSL_CERT) $$flags";                          \
	  fi;                                                                \
	  if test "$(HTTP_PROXY)" != ""; then                                \
	    flags="--http-proxy $(HTTP_PROXY) $$flags";                      \
	  fi;                                                                \
	  if test "$(EXCLUSIVE_WC_LOCKS)" != ""; then                        \
	    flags="--exclusive-wc-locks $$flags";                            \
	  fi;                                                                \
	  if test "$(MEMCACHED_SERVER)" != ""; then                          \
	    flags="--memcached-server $(MEMCACHED_SERVER) $$flags";          \
	  fi;                                                                \
	  LD_LIBRARY_PATH='$(auth_plugin_dirs):$(LD_LIBRARY_PATH)'           \
	  $(PYTHON) $(top_srcdir)/build/run_tests.py                         \
	            --config-file $(top_srcdir)/subversion/tests/tests.conf  \
	            $$flags                                                  \
	            '$(abs_srcdir)' '$(abs_builddir)' $(TESTS);              \
	else                                                                 \
	  echo "make check: Python 2.7 or greater is required,";             \
	  echo "            but was not detected during configure";          \
	  exit 1;                                                            \
	fi;

# First, set up Apache as documented in
# subversion/tests/cmdline/README.
davcheck: bin $(TEST_DEPS)  apache-mod
	@$(MAKE) check BASE_URL=http://localhost

# Automatically configure and run Apache httpd on a random port, and then
# run make check.
davautocheck: bin $(TEST_DEPS)  apache-mod
	@# Takes MODULE_PATH, USE_HTTPV1 and SVN_PATH_AUTHZ in the environment.
	@APXS=$(APXS) MAKE=$(MAKE) $(SHELL) $(top_srcdir)/subversion/tests/cmdline/davautocheck.sh

# First, run:
#   subversion/svnserve/svnserve -d -r `pwd`/subversion/tests/cmdline
svncheck: bin $(TEST_DEPS) 
	@$(MAKE) check BASE_URL=svn://127.0.0.1

# 'make svnserveautocheck' runs svnserve for you and kills it.
svnserveautocheck: svnserve bin $(TEST_DEPS) 
	@env PYTHON=$(PYTHON) THREADED=$(THREADED) MAKE=$(MAKE) \
	  $(SHELL) $(top_srcdir)/subversion/tests/cmdline/svnserveautocheck.sh

# First, run:
#   subversion/svnserve/svnserve --listen-host "::1" -d -r `pwd`/subversion/tests/cmdline

svncheck6: bin $(TEST_DEPS) 
	@$(MAKE) check BASE_URL=svn://\[::1\]

# First make sure you can ssh to localhost and that "svnserve" is in
# the path of the resulting shell.
svnsshcheck: bin $(TEST_DEPS) 
	@$(MAKE) check \
	  BASE_URL=svn+ssh://localhost`pwd`/subversion/tests/cmdline

bdbcheck: bin $(TEST_DEPS) 
	@$(MAKE) check FS_TYPE=bdb

# Produce the clang compilation database as the compile_commands.json file
# in the srcdir.  This is used by tools such as the YouCompleteMe vim plugin
# to know the compile flags for various source files so that analysis such
# as syntax checking, static analysis or symbol completion can be done
# outside the build system.  To do this it uses the tool called bear:
# https://github.com/rizsotto/Bear
compile-commands:
	@bear -o $(abs_srcdir)/compile_commands.json -- $(MAKE) all

# Create an execution coverage report from the data collected during
# all execution since the last reset.
gcov:
	lcov --capture -d . -b . -o gcov-lcov.dat > gcov-lcov.log
	genhtml gcov-lcov.dat -o gcov-report > gcov-genhtml.log

# Reset all execution coverage counters to zero.
gcov-reset:
	lcov --zerocounters -d .

# Remove the execution coverage data and the report.
gcov-clean:
	rm -f gcov-lcov.dat gcov-lcov.log gcov-genhtml.log
	rm -rf gcov-report
	find . -name "*.gcda" -o -name "*.gcno" -exec rm -f -- {} \;

check-clean: gcov-clean
	if [ -d subversion/tests/cmdline/svn-test-work ]; then \
	  rm -rf subversion/tests/cmdline/svn-test-work/*;     \
	fi
	rm -rf subversion/tests/libsvn_fs/test-repo-*          \
	       subversion/tests/libsvn_fs_base/test-repo-*     \
	       subversion/tests/libsvn_fs_fs/test-repo-*       \
	       subversion/tests/libsvn_ra_local/test-repo-*    \
	       subversion/tests/libsvn_repos/test-repo-*       \
	       subversion/tests/libsvn_subr/z                  \
	       subversion/tests/libsvn_wc/fake-wc              \
	       subversion/tests/libsvn_client/test-patch*      \
	       subversion/tests/libsvn_client/test-*/          \
	       subversion/tests/libsvn_diff/B2                 \
	       subversion/tests/libsvn_diff/T1                 \
	       subversion/tests/libsvn_diff/T2                 \
	       subversion/tests/libsvn_diff/T3                 \
	       subversion/tests/svnserveautocheck.pid          \
	       tests.log fails.log

mkdir-init:
	@list='$(BUILD_DIRS) $(SCHEMA_DIR) doc';         \
        for i in $$list; do                              \
            if [ ! -d $$i ]; then                        \
                $(MKDIR) $$i ;                           \
            fi;                                          \
        done

# DOCUMENTATION RULES

# Every single document in every format.
doc: doc-api doc-javahl

# Generate API documentation for the C libraries.
### This could also generate POD for swig-perl, etc.
doc-api: mkdir-init
	( cd $(top_srcdir) && \
	  sed "s,\(OUTPUT_DIRECTORY *= *\),\1$(abs_builddir)/," \
	  doc/doxygen.conf | $(DOXYGEN) - )

# Generate API documentation for the JavaHL package.
doc-javahl:
	$(JAVADOC) -d $(abs_builddir)/doc/javadoc \
	  -sourcepath $(top_srcdir)/subversion/bindings/javahl/src \
	  -link http://java.sun.com/javase/6/docs/api/ \
	  org.tigris.subversion.javahl \
	  org.apache.subversion.javahl \
	  org.apache.subversion.javahl.callback \
	  org.apache.subversion.javahl.remote \
	  org.apache.subversion.javahl.types \
	  org.apache.subversion.javahl.util

doc-clean:
	rm -rf $(abs_builddir)/doc/doxygen
	rm -rf $(abs_builddir)/doc/javadoc

# Converting from the .rnc XML schemas to various other schema formats.
SCHEMAS_DTD = $(SCHEMA_DIR)/blame.dtd \
              $(SCHEMA_DIR)/diff.dtd \
              $(SCHEMA_DIR)/info.dtd \
              $(SCHEMA_DIR)/list.dtd \
              $(SCHEMA_DIR)/log.dtd \
              $(SCHEMA_DIR)/props.dtd \
              $(SCHEMA_DIR)/status.dtd

SCHEMAS_RNG = $(SCHEMA_DIR)/blame.rng \
              $(SCHEMA_DIR)/diff.rng \
              $(SCHEMA_DIR)/info.rng \
              $(SCHEMA_DIR)/list.rng \
              $(SCHEMA_DIR)/log.rng \
              $(SCHEMA_DIR)/props.rng \
              $(SCHEMA_DIR)/status.rng

SCHEMAS_XSD = $(SCHEMA_DIR)/blame.xsd \
              $(SCHEMA_DIR)/diff.xsd \
              $(SCHEMA_DIR)/info.xsd \
              $(SCHEMA_DIR)/list.xsd \
              $(SCHEMA_DIR)/log.xsd \
              $(SCHEMA_DIR)/props.xsd \
              $(SCHEMA_DIR)/status.xsd

schema: mkdir-init schema-rng schema-dtd schema-xsd

schema-rng: $(SCHEMAS_RNG)
schema-dtd: $(SCHEMAS_DTD)
schema-xsd: $(SCHEMAS_XSD)

$(SCHEMAS_RNG) $(SCHEMAS_DTD) $(SCHEMAS_XSD): $(SCHEMA_DIR)/common.rnc

schema-clean:
	(cd $(SCHEMA_DIR) && rm -f *.rng *.dtd *.xsd)

#
# Implicit rules for creating outputs from input files
#
.SUFFIXES:
.SUFFIXES: .c .cpp .lo .o .la-a .la \
           .po .spo .mo .rnc .rng .dtd .xsd .sql .h

.sql.h:
	$(PYTHON) $(top_srcdir)/build/transform_sql.py $< $(top_srcdir)/$@

.c.o:
	$(COMPILE) -o $@ -c $<

.cpp.o:
	$(COMPILE_CXX) -o $@ -c $<

.c.lo:
	$(LT_COMPILE) -o $@ -c $<

.cpp.lo:
	$(LT_COMPILE_CXX) -o $@ -c $<

.la.la-a:
	sed "/library_names/s/'.*'/''/" $< > $@


# Strip the Content-Type: header from the po file if we don't have a
# gettext that supports bind_textdomain_codeset, so it doesn't try
# to convert our UTF-8 .po files to the locale encoding.
#.po.spo:
#	sed \
#	'/^"Content-Type: text\/plain; charset=UTF-8\\n"$$/d' \
#	$< > $@

#.spo.mo:
#	$(MSGFMT) $(MSGFMTFLAGS) -o $@ $<

# For systems with bind_textdomain_codeset, just leave the Content-Type:
# header alone.
.po.mo:
	$(MSGFMT) $(MSGFMTFLAGS) -o $@ $<

.rnc.rng:
	none $< $@

.rnc.dtd:
	none $< $@

.rnc.xsd:
	none $< $@

install-docs: install-man

manroot = $(mandir)/man
install-man:
	@list='$(MANPAGES)';                                               \
        for i in $$list; do                                                \
          if test -f $(srcdir)/$$i; then file=$(srcdir)/$$i;               \
          else file=$$i; fi;                                               \
          ext=`echo $$i | sed -e 's/^.*\\.//'`;                            \
          $(MKDIR) $(DESTDIR)$(manroot)$$ext;                              \
          inst=`echo $$i | sed -e 's/\\.[0-9a-z]*$$//'`;                   \
          inst=`echo $$inst | sed -e 's/^.*\///'`;                         \
          inst=`echo $$inst`.$$ext;                                        \
          echo "$(INSTALL_DATA) $$file $(DESTDIR)$(manroot)$$ext/$$inst";  \
          $(INSTALL_DATA) $$file $(DESTDIR)$(manroot)$$ext/$$inst;         \
        done

install-swig-py: install-swig-py-lib
install-swig-rb: install-swig-rb-lib

clean-bindings: clean-swig clean-ctypes-python clean-javahl

extraclean-bindings: clean-swig extraclean-swig-headers \
			extraclean-swig-py extraclean-swig-rb \
			extraclean-swig-pl \
			clean-ctypes-python clean-javahl \

clean-swig: clean-swig-headers clean-swig-py clean-swig-rb clean-swig-pl
	@rm -f .swig_checked

EXTRACLEAN_SWIG_HEADERS=rm -f $(SWIG_SRC_DIR)/proxy/*.swg

clean-swig-headers:
	if test -z "$(RELEASE_MODE)"; then \
	  $(EXTRACLEAN_SWIG_HEADERS); \
	fi

extraclean-swig-headers: clean-swig-headers
	$(EXTRACLEAN_SWIG_HEADERS)

$(SWIG_PL_DIR)/native/Makefile.PL: $(SWIG_SRC_DIR)/perl/native/Makefile.PL.in
	./config.status subversion/bindings/swig/perl/native/Makefile.PL

$(SWIG_PL_DIR)/native/Makefile: $(SWIG_PL_DIR)/native/Makefile.PL
	cd $(SWIG_PL_DIR)/native; $(PERL) Makefile.PL PREFIX=$(prefix)

# There is a "readlink -f" command on some systems for the same purpose,
# but it's not as portable (e.g. Mac OS X doesn't have it).  These should
# only be used where Python/Perl are known to be available.
READLINK_PY=$(PYTHON) -c 'import sys,os; print(os.path.realpath(sys.argv[1]))'
READLINK_PL=$(PERL) -e 'use Cwd; print Cwd::realpath(shift)'

swig-pl_DEPS = autogen-swig-pl libsvn_swig_perl \
  $(SWIG_PL_DIR)/native/Makefile
swig-pl: $(swig-pl_DEPS)
	if test "`$(READLINK_PL) $(SWIG_PL_DIR)`" != "`$(READLINK_PL) $(SWIG_PL_SRC_DIR)`"; then \
	  ln -sf $(SWIG_PL_SRC_DIR)/native/*.c $(SWIG_PL_DIR)/native; \
	fi
	cd $(SWIG_PL_DIR)/native; $(MAKE) OPTIMIZE="" OTHERLDFLAGS="$(SWIG_LDFLAGS)"

check-swig-pl: swig-pl swig-pl-lib
	cd $(SWIG_PL_DIR)/native; $(MAKE) test

install-swig-pl: swig-pl install-swig-pl-lib
	cd $(SWIG_PL_DIR)/native; $(MAKE) install

EXTRACLEAN_SWIG_PL=rm -f $(SWIG_PL_SRC_DIR)/native/svn_*.c \
                         $(SWIG_PL_SRC_DIR)/native/core.c

# Running Makefile.PL at this point *fails* (cannot find ..../.libs) so if the
# Makefile does not exist, DO NOT try to make it. But, if it doesn't exist,
# then the directory is probably clean anyway.
clean-swig-pl:
	if test -z "$(RELEASE_MODE)"; then \
	  $(EXTRACLEAN_SWIG_PL); \
	fi
	for d in $(SWIG_PL_DIR)/libsvn_swig_perl; \
	do \
	  cd $$d; \
	  rm -rf *.lo *.la *.o .libs; \
	done
	if [ -f "$(SWIG_PL_DIR)/native/Makefile" ]; then \
	  cd $(SWIG_PL_DIR)/native; $(MAKE) clean; \
	fi

extraclean-swig-pl: clean-swig-pl
	$(EXTRACLEAN_SWIG_PL)

$(SWIG_PY_DIR)/libsvn:
	mkdir $(SWIG_PY_DIR)/libsvn

copy-swig-py: autogen-swig-py $(SWIG_PY_DIR)/libsvn
	@for f in $(SWIG_PY_SRC_DIR)/*.py $(SWIG_PY_DIR)/*.py; do \
	  ! [ -f "$$f" ] || cp -pf $$f $(SWIG_PY_DIR)/libsvn; \
	done
	@touch $(SWIG_PY_DIR)/libsvn/__init__.py

swig-py: autogen-swig-py copy-swig-py

check-swig-py: swig-py
	$(TEST_SHLIB_VAR_SWIG_PY) \
	cd $(SWIG_PY_DIR); \
	  $(PYTHON) $(SWIG_PY_SRC_DIR)/tests/run_all.py

EXTRACLEAN_SWIG_PY=rm -rf $(SWIG_PY_SRC_DIR)/svn_*.c $(SWIG_PY_SRC_DIR)/core.c \
                          $(SWIG_PY_SRC_DIR)/[a-z]*.py
clean-swig-py:
	rm -rf $(SWIG_PY_DIR)/libsvn
	if test -z "$(RELEASE_MODE)"; then \
	  $(EXTRACLEAN_SWIG_PY); \
	fi
	for d in $(SWIG_PY_DIR) $(SWIG_PY_DIR)/libsvn_swig_py; \
	do \
	  cd $$d && rm -rf *.lo *.la *.o *.pyc .libs; \
	done
	find $(SWIG_PY_SRC_DIR) $(SWIG_PY_DIR) -name "*.pyc" -exec rm {} ';'

extraclean-swig-py: clean-swig-py
	$(EXTRACLEAN_SWIG_PY)

swig-rb: autogen-swig-rb

check-swig-rb: swig-rb svnserve
	$(TEST_SHLIB_VAR_SWIG_RB) \
	cd $(SWIG_RB_DIR); \
          if [ "$(RUBY_MAJOR)" -eq 1 -a "$(RUBY_MINOR)" -lt 9 ] ; then \
            $(RUBY) -I $(SWIG_RB_SRC_DIR) \
              $(SWIG_RB_SRC_DIR)/test/run-test.rb \
	      --verbose=$(SWIG_RB_TEST_VERBOSE); \
          else \
	    $(RUBY) -I $(SWIG_RB_SRC_DIR) \
	      $(SWIG_RB_SRC_DIR)/test/run-test.rb; \
          fi

EXTRACLEAN_SWIG_RB=rm -f $(SWIG_RB_SRC_DIR)/svn_*.c $(SWIG_RB_SRC_DIR)/core.c

clean-swig-rb:
	rm -rf $(SWIG_RB_DIR)/test/repos $(SWIG_RB_DIR)/test/wc
	if test -z "$(RELEASE_MODE)"; then \
	  $(EXTRACLEAN_SWIG_RB); \
	fi
	for d in $(SWIG_RB_DIR) $(SWIG_RB_DIR)/libsvn_swig_ruby; \
	do \
	  cd $$d; \
	  rm -rf *.lo *.la *.o .libs; \
	done

extraclean-swig-rb: clean-swig-rb
	$(EXTRACLEAN_SWIG_RB)

install-swig-rb-doc:
	$(RDOC) --all --ri --op "$(SWIG_RB_RI_DATADIR)" "$(SWIG_RB_SRC_DIR)/svn"

# ctypes-python make targets
ctypes-python: local-all
	$(SHELL) $(abs_srcdir)/build/run_ctypesgen.sh "$(LT_EXECUTE)" "$(CPPFLAGS)" "$(EXTRA_CTYPES_LDFLAGS)" "$(PYTHON)" "$(CTYPESGEN)" "$(abs_srcdir)" "$(abs_builddir)" "$(libdir)" "$(SVN_APR_CONFIG)" "$(SVN_APRUTIL_CONFIG)" "$(CPP)"

install-ctypes-python: ctypes-python
	cd $(CTYPES_PYTHON_SRC_DIR); \
	  $(PYTHON) setup.py install --prefix="$(DESTDIR)$(prefix)"

check-ctypes-python: ctypes-python
	cd $(CTYPES_PYTHON_SRC_DIR); \
	  $(LT_EXECUTE) $(PYTHON) test/run_all.py

# If any of those files exists, run ctypes' 'setup.py clean'.  We don't run
# it otherwise because it spams stdout+stderr; see r1479326.
clean-ctypes-python:
	cd $(CTYPES_PYTHON_SRC_DIR);            \
	  for b in build csvn/core/functions.py svn_all.py svn_all2.py ; do \
	    if [ -e "$$b" ] ; then              \
	      $(PYTHON) setup.py clean --all;   \
	      break;                            \
	    fi;                                 \
	  done

# manually describe a dependency, which we won't otherwise detect
subversion/libsvn_wc/wc-queries.h: $(abs_srcdir)/subversion/libsvn_wc/wc-metadata.sql
subversion/libsvn_wc/wc-queries.h: $(abs_srcdir)/subversion/libsvn_wc/wc-checks.sql

# Compatibility symlink.
# This runs after the target of the same name in build-outputs.mk.
INSTALL_EXTRA_TOOLS=\
  $(MKDIR) $(DESTDIR)$(bindir); \
  test -n "$$SVN_SVNMUCC_IS_SVNSYITF" && \
  ln -sf svnmucc$(EXEEXT) $(DESTDIR)$(bindir)/svnsyitf$(EXEEXT); \
  if test "$(DESTDIR)$(bindir)" != "$(DESTDIR)$(toolsdir)"; then \
    ln -sf $(bindir)/svnmucc$(EXEEXT) $(DESTDIR)$(toolsdir)/svnmucc$(EXEEXT); \
    ln -sf $(bindir)/svnbench$(EXEEXT) $(DESTDIR)$(toolsdir)/svn-bench$(EXEEXT); \
  fi
