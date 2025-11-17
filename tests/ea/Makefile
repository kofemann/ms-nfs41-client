#
# Makefile for nfs_ea
#

# signtool.exe can be in either '/cygdrive/c/Program Files/' or '/cygdrive/c/Program Files (x86)/'
SIGNTOOL := $(shell ls -1 '/cygdrive/c/Program Files'*'/Microsoft SDKs/ClickOnce/SignTool/signtool.exe' | head -n 1)

all: nfs_ea.i686.exe nfs_ea.x86_64.exe nfs_ea.exe

nfs_ea.i686.exe: main.c
	clang -target i686-pc-windows-gnu -std=gnu17 -municode -Wall -Wextra -DSTRSAFE_NO_DEPRECATE=1 -D_CRT_STDIO_ISO_WIDE_SPECIFIERS=1 -DUNICODE=1 -D_UNICODE=1 -isystem /usr/include/w32api/ddk -I../../include -g main.c -lntdll -o $@
	bash -x -c '"$(SIGNTOOL)" sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

nfs_ea.x86_64.exe: main.c
	clang -target x86_64-pc-windows-gnu -std=gnu17 -municode -Wall -Wextra -DSTRSAFE_NO_DEPRECATE=1 -D_CRT_STDIO_ISO_WIDE_SPECIFIERS=1 -DUNICODE=1 -D_UNICODE=1 -isystem /usr/include/w32api/ddk -I../../include -g main.c -lntdll -o $@
	bash -x -c '"$(SIGNTOOL)" sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

nfs_ea.exe: nfs_ea.x86_64.exe
	rm -f nfs_ea.exe
	ln -s nfs_ea.x86_64.exe nfs_ea.exe

clean:
	rm -fv \
		nfs_ea.i686.exe \
		nfs_ea.x86_64.exe \
		nfs_ea.exe
# EOF.
