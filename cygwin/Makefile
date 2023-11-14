#
# ms-nfs41-client/cygwin/Makefile
#
# Simple (Cygwin) Makfile for quick&dirty nfsd_debug.exe testing
#
# Written by Roland Mainz <roland.mainz@nrubsig.org>
#

SHELL := /bin/bash

CYGWIN_MAKEFILE_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
PROJECT_BASEDIR_DIR := $(shell dirname $(realpath $(CYGWIN_MAKEFILE_DIR)/))

DESTDIR:=$(PROJECT_BASEDIR_DIR)/destdir

VS_BUILD_DIR:=$(PROJECT_BASEDIR_DIR)/build.vc19/x64/Debug/

# trigger "build" target when these binaries are needed
$(VS_BUILD_DIR)/nfsd.exe \
	$(VS_BUILD_DIR)/nfs_mount.exe \
	$(VS_BUILD_DIR)/nfs_install.exe \
	$(VS_BUILD_DIR)/nfs_mount.exe \
	$(VS_BUILD_DIR)/nfs41_driver.sys \
	$(VS_BUILD_DIR)/libtirpc.dll: build

#
# build the code
#
build:
	@printf '#\n# PATH is %q\n#\n' '$(PATH)'
	which MSBuild.exe
	MSBuild.exe '$(shell cygpath -w "$(PROJECT_BASEDIR_DIR)/build.vc19/nfs41-client.sln")' -t:Build  -p:Configuration=Debug -p:Platform=x64
	#MSBuild.exe $(PROJECT_BASEDIR_DIR)/build.vc19/nfs41-client.sln -t:Build  -p:Configuration=Debug -p:Platform=x64


#
# clean target
#
clean:
	rm -vRf $$(find "$(PROJECT_BASEDIR_DIR)/build.vc19" -name Debug -o -name Release)

# install in DESTDIR
installdest: $(VS_BUILD_DIR)/nfsd.exe \
	$(VS_BUILD_DIR)/nfs_mount.exe \
	$(VS_BUILD_DIR)/nfs_install.exe \
	$(VS_BUILD_DIR)/nfs_mount.exe \
	$(VS_BUILD_DIR)/nfs41_driver.sys \
	$(VS_BUILD_DIR)/libtirpc.dll \
	$(PROJECT_BASEDIR_DIR)/nfs41rdr.inf \
	$(PROJECT_BASEDIR_DIR)/etc_netconfig \
	$(PROJECT_BASEDIR_DIR)/ms-nfs41-idmap.conf \
	$(CYGWIN_MAKEFILE_DIR)/devel/msnfs41client.bash
	@if [[ "$$(ps -ef)" =~ "$(DESTDIR)" ]] ; then \
		printf 'DIR %q is in use by a process\n' "$DESTDIR" 1>&2 ; \
		exit 1 ; \
	fi
	mkdir -p $(DESTDIR)
	mkdir -p $(DESTDIR)/cygdrive/c/cygwin64/sbin/
	cp -r $(VS_BUILD_DIR)/nfsd.exe		$(DESTDIR)/cygdrive/c/cygwin64/sbin/nfsd_debug.exe
	cp -r $(VS_BUILD_DIR)/nfsd.pdb		$(DESTDIR)/cygdrive/c/cygwin64/sbin/nfsd_debug.pdb
	cp -r $(VS_BUILD_DIR)/nfs_mount.*	$(DESTDIR)/cygdrive/c/cygwin64/sbin/.
	cp -r $(VS_BUILD_DIR)/nfsd.*		$(DESTDIR)/cygdrive/c/cygwin64/sbin/.
	cp -r $(VS_BUILD_DIR)/nfs_install.*	$(DESTDIR)/cygdrive/c/cygwin64/sbin/.
	cp -r $(VS_BUILD_DIR)/nfs41_np.*	$(DESTDIR)/cygdrive/c/cygwin64/sbin/.
	cp -r $(VS_BUILD_DIR)/nfs41_driver.*	$(DESTDIR)/cygdrive/c/cygwin64/sbin/.
	cp -r $(VS_BUILD_DIR)/libtirpc.*	$(DESTDIR)/cygdrive/c/cygwin64/sbin/.
	cp $(PROJECT_BASEDIR_DIR)/nfs41rdr.inf	$(DESTDIR)/cygdrive/c/cygwin64/sbin/.
	cp $(PROJECT_BASEDIR_DIR)/etc_netconfig	$(DESTDIR)/cygdrive/c/cygwin64/sbin/.
	cp $(PROJECT_BASEDIR_DIR)/ms-nfs41-idmap.conf $(DESTDIR)/cygdrive/c/cygwin64/sbin/.
	cp $(CYGWIN_MAKEFILE_DIR)/devel/msnfs41client.bash $(DESTDIR)/cygdrive/c/cygwin64/sbin/.
	(cd $(DESTDIR)/cygdrive/c/cygwin64/sbin/ ; chmod a+x *.exe *.dll *.sys *.bash)
	@printf "\n#\n# TEST sbin dir is %s\n#\n" "$(DESTDIR)/cygdrive/c/cygwin64/sbin/"
	@printf '\n'
	@printf "\n#\n# Now use\n# $$ cd '%s' && bash ./msnfs41client.bash install #\n# to install the kernel driver as Admin\n#\n" \
		"$(DESTDIR)/cygdrive/c/cygwin64/sbin/"

#
# clean destdir/, but only if nfsd*.exe does not use it right now
#
cleandest:
	@if [[ "$$(ps -ef)" =~ "$(DESTDIR)" ]] ; then \
		printf 'DIR %q is in use by a process\n' "$DESTDIR" 1>&2 ; \
		exit 1 ; \
	fi
	rm -r "$(DESTDIR)"

# EOF.
