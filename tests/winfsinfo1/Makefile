#
# Makefile for winfsinfo
#

# signtool.exe can be in either '/cygdrive/c/Program Files/' or '/cygdrive/c/Program Files (x86)/'
SIGNTOOL := $(shell ls -1 '/cygdrive/c/Program Files'*'/Microsoft SDKs/ClickOnce/SignTool/signtool.exe' | head -n 1)

all: winfsinfo.i686.exe winfsinfo.x86_64.exe winfsinfo.exe

winfsinfo.i686.exe: winfsinfo.c
	clang -target i686-pc-windows-gnu -std=gnu17 -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -I../../include -g winfsinfo.c -lmpr -lntdll -o $@
	bash -x -c '"$(SIGNTOOL)" sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

winfsinfo.x86_64.exe: winfsinfo.c
	clang -target x86_64-pc-windows-gnu -std=gnu17 -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -I../../include -g winfsinfo.c -lmpr -lntdll -o $@
	bash -x -c '"$(SIGNTOOL)" sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

winfsinfo.exe: winfsinfo.x86_64.exe
	ln -s winfsinfo.x86_64.exe winfsinfo.exe

clean:
	rm -fv \
		winfsinfo.i686.exe \
		winfsinfo.x86_64.exe \
		winfsinfo.exe
# EOF.
