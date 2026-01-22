#
# Makefile for winstreamsutil
#

# signtool.exe can be in either '/cygdrive/c/Program Files/' or '/cygdrive/c/Program Files (x86)/'
SIGNTOOL := $(shell ls -1 '/cygdrive/c/Program Files'*'/Microsoft SDKs/ClickOnce/SignTool/signtool.exe' | head -n 1)

all: winstreamsutil.i686.exe winstreamsutil.x86_64.exe winstreamsutil.exe

winstreamsutil.i686.exe: winstreamsutil.c
	clang -target i686-pc-windows-gnu -std=gnu17 -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -municode -I../../include -g winstreamsutil.c -lntdll -o $@
	bash -x -c '"$(SIGNTOOL)" sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

winstreamsutil.x86_64.exe: winstreamsutil.c
	clang -target x86_64-pc-windows-gnu -std=gnu17 -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -municode -I../../include -g winstreamsutil.c -lntdll -o $@
	bash -x -c '"$(SIGNTOOL)" sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

winstreamsutil.exe: winstreamsutil.x86_64.exe
	ln -s winstreamsutil.x86_64.exe winstreamsutil.exe

clean:
	rm -fv \
		winstreamsutil.i686.exe \
		winstreamsutil.x86_64.exe \
		winstreamsutil.exe
# EOF.
