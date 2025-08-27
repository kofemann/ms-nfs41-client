#
# Makefile for winoffloadcopyfile
#

# POSIX Makefile
SIGNTOOL="/cygdrive/c/Program Files (x86)/Microsoft SDKs/ClickOnce/SignTool/signtool.exe"

all: winoffloadcopyfile.i686.exe winoffloadcopyfile.x86_64.exe winoffloadcopyfile.exe

winoffloadcopyfile.i686.exe: winoffloadcopyfile.c
	clang -target i686-pc-windows-gnu -std=gnu17 -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -I../../include -g winoffloadcopyfile.c -lntdll -o $@
	bash -x -c '$(SIGNTOOL) sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

winoffloadcopyfile.x86_64.exe: winoffloadcopyfile.c
	clang -target x86_64-pc-windows-gnu -std=gnu17 -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -I../../include -g winoffloadcopyfile.c -lntdll -o $@
	bash -x -c '$(SIGNTOOL) sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

winoffloadcopyfile.exe: winoffloadcopyfile.x86_64.exe
	ln -s winoffloadcopyfile.x86_64.exe winoffloadcopyfile.exe

clean:
	rm -fv \
		winoffloadcopyfile.i686.exe \
		winoffloadcopyfile.x86_64.exe \
		winoffloadcopyfile.exe
# EOF.
