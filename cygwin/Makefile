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

VS_BUILD_DIR32:=$(PROJECT_BASEDIR_DIR)/build.vc19/Debug/
VS_BUILD_DIR64:=$(PROJECT_BASEDIR_DIR)/build.vc19/x64/Debug/
#VS_BUILD_DIR32:=$(PROJECT_BASEDIR_DIR)/build.vc19/Release/
#VS_BUILD_DIR64:=$(PROJECT_BASEDIR_DIR)/build.vc19/x64/Release/

# trigger "build" target when these binaries are needed
$(VS_BUILD_DIR32)/nfsd.exe \
	$(VS_BUILD_DIR32)/nfs_mount.exe \
	$(VS_BUILD_DIR32)/nfs_install.exe \
	$(VS_BUILD_DIR32)/nfs_mount.exe \
	$(VS_BUILD_DIR32)/nfs41_driver.sys \
	$(VS_BUILD_DIR32)/libtirpc.dll \
	$(VS_BUILD_DIR64)/nfsd.exe \
	$(VS_BUILD_DIR64)/nfs_mount.exe \
	$(VS_BUILD_DIR64)/nfs_install.exe \
	$(VS_BUILD_DIR64)/nfs_mount.exe \
	$(VS_BUILD_DIR64)/nfs41_driver.sys \
	$(VS_BUILD_DIR64)/libtirpc.dll: build

# trigger "build_testutils" target when these binaries are needed
$(PROJECT_BASEDIR_DIR)/tests/ea/nfs_ea.exe \
	$(PROJECT_BASEDIR_DIR)/tests/winfsinfo1/winfsinfo.exe \
	$(PROJECT_BASEDIR_DIR)/tests/winsg/winsg.exe: build_testutils

#
# build the code
#
build_64bit_release:
	@printf '#\n# PATH is %q\n#\n' '$(PATH)'
	which MSBuild.exe
	MSBuild.exe '$(shell cygpath -w "$(PROJECT_BASEDIR_DIR)/build.vc19/nfs41-client.sln")' -t:Build  -p:Configuration=Release -p:Platform=x64

build_64bit_debug:
	@printf '#\n# PATH is %q\n#\n' '$(PATH)'
	which MSBuild.exe
	MSBuild.exe '$(shell cygpath -w "$(PROJECT_BASEDIR_DIR)/build.vc19/nfs41-client.sln")' -t:Build  -p:Configuration=Debug -p:Platform=x64

build_32bit_release:
	@printf '#\n# PATH is %q\n#\n' '$(PATH)'
	which MSBuild.exe
	MSBuild.exe '$(shell cygpath -w "$(PROJECT_BASEDIR_DIR)/build.vc19/nfs41-client.sln")' -t:Build  -p:Configuration=Release -p:Platform=x86

build_32bit_debug:
	@printf '#\n# PATH is %q\n#\n' '$(PATH)'
	which MSBuild.exe
	MSBuild.exe '$(shell cygpath -w "$(PROJECT_BASEDIR_DIR)/build.vc19/nfs41-client.sln")' -t:Build  -p:Configuration=Debug -p:Platform=x86

build_arm_64bit_debug:
	@printf '#\n# PATH is %q\n#\n' '$(PATH)'
	which MSBuild.exe
	MSBuild.exe '$(shell cygpath -w "$(PROJECT_BASEDIR_DIR)/build.vc19/nfs41-client.sln")' -t:Build  -p:Configuration=Debug -p:Platform=ARM64

build_testutils:
	(cd "$(PROJECT_BASEDIR_DIR)/tests/ea" && make all)
	(cd "$(PROJECT_BASEDIR_DIR)/tests/winfsinfo1" && make all)
	(cd "$(PROJECT_BASEDIR_DIR)/tests/winsg" && make all)

build: build_32bit_release build_32bit_debug build_64bit_release build_64bit_debug build_arm_64bit_debug build_testutils
	sync

#
# clean target
#
clean:
	rm -vRf $$(find "$(PROJECT_BASEDIR_DIR)/build.vc19" -name Debug -o -name Release)
	(cd "$(PROJECT_BASEDIR_DIR)/tests/ea" && make clean)
	(cd "$(PROJECT_BASEDIR_DIR)/tests/winfsinfo1" && make clean)
	(cd "$(PROJECT_BASEDIR_DIR)/tests/winsg" && make clean)

installdest_util: \
	$(PROJECT_BASEDIR_DIR)/nfs41rdr.inf \
	$(PROJECT_BASEDIR_DIR)/etc_netconfig \
	$(PROJECT_BASEDIR_DIR)/ms-nfs41-idmap.conf \
	$(PROJECT_BASEDIR_DIR)/tests/ea/nfs_ea.exe \
	$(PROJECT_BASEDIR_DIR)/tests/winfsinfo1/winfsinfo.exe \
	$(PROJECT_BASEDIR_DIR)/tests/winsg/winsg.exe \
	$(CYGWIN_MAKEFILE_DIR)/devel/msnfs41client.bash

installdest32: \
	$(VS_BUILD_DIR32)/nfsd.exe \
	$(VS_BUILD_DIR32)/nfs_mount.exe \
	$(VS_BUILD_DIR32)/nfs_install.exe \
	$(VS_BUILD_DIR32)/nfs_mount.exe \
	$(VS_BUILD_DIR32)/nfs41_driver.sys \
	$(VS_BUILD_DIR32)/libtirpc.dll \
	# installdest 32bit Windows
	make -f $(CYGWIN_MAKEFILE_DIR)/Makefile.install \
		installdest \
		VS_BUILD_DIR="$(VS_BUILD_DIR32)" \
		CYGWIN_BASEPATH=/cygdrive/c/cygwin/

installdest64: \
	$(VS_BUILD_DIR64)/nfsd.exe \
	$(VS_BUILD_DIR64)/nfs_mount.exe \
	$(VS_BUILD_DIR64)/nfs_install.exe \
	$(VS_BUILD_DIR64)/nfs_mount.exe \
	$(VS_BUILD_DIR64)/nfs41_driver.sys \
	$(VS_BUILD_DIR64)/libtirpc.dll \
	# installdest 64bit Windows
	make -f $(CYGWIN_MAKEFILE_DIR)/Makefile.install \
		installdest \
		VS_BUILD_DIR="$(VS_BUILD_DIR64)" \
		CYGWIN_BASEPATH=/cygdrive/c/cygwin64/

# installdest: we need a .WAIT here becase Makefile.install uses git commands
# to create a git bundle, and the commands do not like to run
# in parallel
installdest: installdest_util installdest32 .WAIT installdest64

bintarball: installdest
	set -o errexit ; set -o xtrace ; \
	base_filename="msnfs41client_cygwin_binaries_$$(date +%Y%m%d_%Hh%Mm)_git$$(git rev-parse --short HEAD)" ; \
	( \
	cd "$(DESTDIR)" && \
	tar -cvf - \
		--owner=SYSTEM:18 \
		--group=SYSTEM:18 \
		cygdrive/c/cygwin \
		cygdrive/c/cygwin64 \
		| \
			bzip2 -9 >"$${base_filename}.tar.bz2" ; \
	archive_sha256hash="$$(openssl sha256 -r "$${base_filename}.tar.bz2" | while read a dummy ; do printf "%s\n" "$$a" ; done)" ; \
		sed -E <"../cygwin/README.bintarball.txt" \
			-e "s/\\$$\{bintarball.base_filename\}/$${base_filename}/g" \
			-e "s/\\$$\{bintarball.archive_sha256hash\}/$${archive_sha256hash}/g" >"$${base_filename}.readme" \
	) ; \
	printf "\n#\n# tarball is ready now\n#\n" ; \
	ls -l "$(DESTDIR)/$${base_filename}.tar.bz2" ; \
	ls -l "$(DESTDIR)/$${base_filename}.readme"
	sync

#
# clean destdir/, but only if nfsd*.exe does not use it right now
#
cleandest:
	@if [[ "$$(ps -ef)" =~ "$(DESTDIR)" ]] ; then \
		printf 'DIR %q is in use by a process\n' "$DESTDIR" 1>&2 ; \
		exit 1 ; \
	fi
	rm -rvf "$(DESTDIR)"

# EOF.
