#
# Makefile for catdbgprint
#

# signtool.exe can be in either '/cygdrive/c/Program Files/' or '/cygdrive/c/Program Files (x86)/'
SIGNTOOL := $(shell ls -1 '/cygdrive/c/Program Files'*'/Microsoft SDKs/ClickOnce/SignTool/signtool.exe' | head -n 1)

all: catdbgprint.i686.exe catdbgprint.x86_64.exe catdbgprint.exe

catdbgprint.i686.exe: catdbgprint.c
	clang -target i686-pc-windows-gnu -std=gnu17 -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -I../../include -g catdbgprint.c -lntdll -o $@
	bash -x -c '"$(SIGNTOOL)" sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

catdbgprint.x86_64.exe: catdbgprint.c
	clang -target x86_64-pc-windows-gnu -std=gnu17 -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -I../../include -g catdbgprint.c -lntdll -o $@
	bash -x -c '"$(SIGNTOOL)" sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

catdbgprint.exe: catdbgprint.x86_64.exe
	ln -s catdbgprint.x86_64.exe catdbgprint.exe

clean:
	rm -fv \
		catdbgprint.i686.exe \
		catdbgprint.x86_64.exe \
		catdbgprint.exe
# EOF.
