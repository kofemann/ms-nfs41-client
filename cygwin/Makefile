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
	MSBuild.exe '$(shell cygpath -w "$(PROJECT_BASEDIR_DIR)/build.vc19/nfs41-client.sln")' -t:Build  -p:Configuration=Release -p:Platform=x64
	MSBuild.exe '$(shell cygpath -w "$(PROJECT_BASEDIR_DIR)/build.vc19/nfs41-client.sln")' -t:Build  -p:Configuration=Debug -p:Platform=x64
	(cd "$(PROJECT_BASEDIR_DIR)/tests/winfsinfo1" && make all)

#
# clean target
#
clean:
	rm -vRf $$(find "$(PROJECT_BASEDIR_DIR)/build.vc19" -name Debug -o -name Release)
	(cd "$(PROJECT_BASEDIR_DIR)/tests/winfsinfo1" && make clean)

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
	@if [[ "$$(ps -ef | grep -v -E "[[:space:]]+$${BASH_PID}[[:space:]]+")" =~ "$(DESTDIR)" ]] ; then \
		printf 'DIR %q is in use by a process\n' "$DESTDIR" 1>&2 ; \
		exit 1 ; \
	fi
	mkdir -p $(DESTDIR)
	mkdir -p $(DESTDIR)/cygdrive/c/cygwin64/sbin/
	# /usr/bin is a bind mount to C:/cygwin64/bin, so copy binaries to /cygdrive/c/cygwin64/bin
	mkdir -p $(DESTDIR)/cygdrive/c/cygwin64/bin
	# /usr/lib is a bind mount to C:/cygwin64/lib, so copy library data to /cygdrive/c/cygwin64/lib
	mkdir -p $(DESTDIR)/cygdrive/c/cygwin64/lib
	mkdir -p $(DESTDIR)/cygdrive/c/cygwin64/lib/msnfs41client
	mkdir -p $(DESTDIR)/cygdrive/c/cygwin64/usr/src/msnfs41client
	mkdir -p $(DESTDIR)/cygdrive/c/cygwin64/usr/share/man/man1
	cp -r $(VS_BUILD_DIR)/nfsd.exe		$(DESTDIR)/cygdrive/c/cygwin64/sbin/nfsd_debug.exe
	cp -r $(VS_BUILD_DIR)/nfsd.pdb		$(DESTDIR)/cygdrive/c/cygwin64/sbin/nfsd_debug.pdb
	cp -r $(VS_BUILD_DIR)/nfs_mount.*	$(DESTDIR)/cygdrive/c/cygwin64/sbin/.
	cp -r $(VS_BUILD_DIR)/nfsd.*		$(DESTDIR)/cygdrive/c/cygwin64/sbin/.
	cp -r $(VS_BUILD_DIR)/nfs_install.*	$(DESTDIR)/cygdrive/c/cygwin64/sbin/.
	cp -r $(VS_BUILD_DIR)/libtirpc.*	$(DESTDIR)/cygdrive/c/cygwin64/sbin/.
	cp -r $(VS_BUILD_DIR)/nfs41_np.*	$(DESTDIR)/cygdrive/c/cygwin64/lib/msnfs41client/.
	cp -r $(VS_BUILD_DIR)/nfs41_driver.*	$(DESTDIR)/cygdrive/c/cygwin64/lib/msnfs41client/.
	cp $(PROJECT_BASEDIR_DIR)/nfs41rdr.inf	$(DESTDIR)/cygdrive/c/cygwin64/lib/msnfs41client/.
	cp $(PROJECT_BASEDIR_DIR)/etc_netconfig	$(DESTDIR)/cygdrive/c/cygwin64/lib/msnfs41client/.
	cp $(PROJECT_BASEDIR_DIR)/ms-nfs41-idmap.conf		$(DESTDIR)/cygdrive/c/cygwin64/lib/msnfs41client/.
	cp $(CYGWIN_MAKEFILE_DIR)/devel/msnfs41client.bash	$(DESTDIR)/cygdrive/c/cygwin64/lib/msnfs41client/msnfs41client
	chmod a+x "$(DESTDIR)/cygdrive/c/cygwin64/lib/msnfs41client/msnfs41client"
	(cd "$(DESTDIR)/cygdrive/c/cygwin64/sbin/" && ln -sf ../lib/msnfs41client/msnfs41client .)
	cp $(PROJECT_BASEDIR_DIR)/cygwin_idmapper.ksh		$(DESTDIR)/cygdrive/c/cygwin64/lib/msnfs41client/.
	@ printf "# Package sources and diffs\n"
	git bundle create "$(DESTDIR)/cygdrive/c/cygwin64/usr/src/msnfs41client/msnfs41client_git.bundle" HEAD
	git diff -w	>"$(DESTDIR)/cygdrive/c/cygwin64/usr/src/msnfs41client/msnfs41client_diff_w.diff"
	git diff	>"$(DESTDIR)/cygdrive/c/cygwin64/usr/src/msnfs41client/msnfs41client_diff.diff"
	@ printf "# Package utilties\n"
	cp $(CYGWIN_MAKEFILE_DIR)/utils/mount_sshnfs/mount_sshnfs.ksh $(DESTDIR)/cygdrive/c/cygwin64/sbin/mount_sshnfs
	chmod a+x $(DESTDIR)/cygdrive/c/cygwin64/sbin/mount_sshnfs
	PATH+=":$(DESTDIR)/cygdrive/c/cygwin64/sbin/" \
		/usr/bin/ksh93 $(CYGWIN_MAKEFILE_DIR)/utils/mount_sshnfs/mount_sshnfs.ksh --nroff 2>"$(DESTDIR)/cygdrive/c/cygwin64/usr/share/man/man1/mount_sshnfs.1" || true
	cp $(CYGWIN_MAKEFILE_DIR)/utils/sshnfs/sshnfs.ksh $(DESTDIR)/cygdrive/c/cygwin64/sbin/sshnfs
	chmod a+x $(DESTDIR)/cygdrive/c/cygwin64/sbin/sshnfs
	cp $(CYGWIN_MAKEFILE_DIR)/utils/nfsurlconv/nfsurlconv.ksh $(DESTDIR)/cygdrive/c/cygwin64/bin/nfsurlconv
	chmod a+x $(DESTDIR)/cygdrive/c/cygwin64/bin/nfsurlconv
	/usr/bin/ksh93 $(CYGWIN_MAKEFILE_DIR)/utils/nfsurlconv/nfsurlconv.ksh --nroff 2>"$(DESTDIR)/cygdrive/c/cygwin64/usr/share/man/man1/nfsurlconv.1" || true
	@ printf "# Package tests\n"
	cp "$(PROJECT_BASEDIR_DIR)/tests/winfsinfo1/winfsinfo.exe" $(DESTDIR)/cygdrive/c/cygwin64/bin/winfsinfo.exe
	@ printf "# Package ksh93&co (if available) since Cygwin does not ship with it yet\n"
	[[ -x /usr/bin/ksh93.exe ]] && cp /usr/bin/ksh93.exe $(DESTDIR)/cygdrive/c/cygwin64/bin/ksh93.exe
	[[ -x /usr/bin/shcomp.exe ]] && cp /usr/bin/shcomp.exe $(DESTDIR)/cygdrive/c/cygwin64/bin/shcomp.exe
	@ printf "# Set file flags\n"
	(cd $(DESTDIR)/cygdrive/c/cygwin64/sbin/ && chmod a+x *.exe *.dll)
	(cd $(DESTDIR)/cygdrive/c/cygwin64/lib/msnfs41client/ && chmod a+x *.dll)
	@printf "\n#\n# TEST sbin dir is %s\n#\n" "$(DESTDIR)/cygdrive/c/cygwin64/sbin/"
	@printf '\n'
	@printf "\n#\n# Now use\n# $$ cd '%s' && ./msnfs41client install #\n# to install the kernel driver as Admin\n#\n" \
		"$(DESTDIR)/cygdrive/c/cygwin64/sbin/"

bintarball: installdest
	set -o errexit ; set -o xtrace ; \
	base_filename="msnfs41client_cygwin_binaries_$$(date +%Y%m%d_%Hh%Mm)_git$$(git rev-parse --short HEAD)" ; \
	( \
	cd "$(DESTDIR)" && \
	tar -cvf - \
		--owner=SYSTEM:18 \
		--group=SYSTEM:18 \
		cygdrive/c/cygwin64 | \
			bzip2 -9 >"$${base_filename}.tar.bz2" ; \
	archive_sha256hash="$$(openssl sha256 -r "$${base_filename}.tar.bz2" | while read a dummy ; do printf "%s\n" "$$a" ; done)" ; \
		sed -E <"../cygwin/README.bintarball.txt" \
			-e "s/\\$$\{bintarball.base_filename\}/$${base_filename}/g" \
			-e "s/\\$$\{bintarball.archive_sha256hash\}/$${archive_sha256hash}/g" >"$${base_filename}.readme" \
	) ; \
	printf "\n#\n# tarball is ready now\n#\n" ; \
	ls -l "$(DESTDIR)/$${base_filename}.tar.bz2" ; \
	ls -l "$(DESTDIR)/$${base_filename}.readme"

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
