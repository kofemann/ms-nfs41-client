#
# Makefile for winrunassystem
#

# signtool.exe can be in either '/cygdrive/c/Program Files/' or '/cygdrive/c/Program Files (x86)/'
SIGNTOOL := $(shell ls -1 '/cygdrive/c/Program Files'*'/Microsoft SDKs/ClickOnce/SignTool/signtool.exe' | head -n 1)

all: \
	winrunassystem.i686.exe \
	winrunassystem.x86_64.exe \
	winrunassystem.exe \
	nfs_globalmount.i686.exe \
	nfs_globalmount.x86_64.exe \
	nfs_globalmount.exe

#
# winrunassystem.exe
#
winrunassystem.i686.exe: winrunassystem.c
	clang -target i686-pc-windows-gnu -std=gnu17 -municode -Wall -Wextra -DBUILD_WINRUNASSYSTEM=1 -DUNICODE=1 -D_UNICODE=1 -g winrunassystem.c -lWtsapi32 -o $@
	bash -x -c '"$(SIGNTOOL)" sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

winrunassystem.x86_64.exe: winrunassystem.c
	clang -target x86_64-pc-windows-gnu -std=gnu17 -municode -Wall -Wextra -DBUILD_WINRUNASSYSTEM=1 -DUNICODE=1 -D_UNICODE=1 -g winrunassystem.c -lWtsapi32 -o $@
	bash -x -c '"$(SIGNTOOL)" sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

winrunassystem.exe: winrunassystem.x86_64.exe
	ln -s winrunassystem.x86_64.exe $@


#
# nfs_globalmount.exe
#
# (implemented *.exe instead of a script,so it can be easily called from
# cmd.exe, powershell.exe, and be whitelisted in MS Defender)
#
nfs_globalmount.i686.exe: winrunassystem.c
	clang -target i686-pc-windows-gnu -std=gnu17 -municode -Wall -Wextra -DBUILD_NFS_GLOBALMOUNT=1 -DUNICODE=1 -D_UNICODE=1 -g winrunassystem.c -lWtsapi32 -o $@
	bash -x -c '"$(SIGNTOOL)" sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

nfs_globalmount.x86_64.exe: winrunassystem.c
	clang -target x86_64-pc-windows-gnu -std=gnu17 -municode -Wall -Wextra -DBUILD_NFS_GLOBALMOUNT=1 -DUNICODE=1 -D_UNICODE=1 -g winrunassystem.c -lWtsapi32 -o $@
	bash -x -c '"$(SIGNTOOL)" sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

nfs_globalmount.exe: nfs_globalmount.x86_64.exe
	ln -s nfs_globalmount.x86_64.exe $@

clean:
	rm -fv \
		winrunassystem.i686.exe \
		winrunassystem.x86_64.exe \
		winrunassystem.exe \
		nfs_globalmount.i686.exe \
		nfs_globalmount.x86_64.exe \
		nfs_globalmount.exe
# EOF.
