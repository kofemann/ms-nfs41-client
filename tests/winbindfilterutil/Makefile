#
# Makefile for winbindfilterutil
#

# signtool.exe can be in either '/cygdrive/c/Program Files/' or '/cygdrive/c/Program Files (x86)/'
SIGNTOOL := $(shell ls -1 '/cygdrive/c/Program Files'*'/Microsoft SDKs/ClickOnce/SignTool/signtool.exe' | head -n 1)

COMMON_CFLAGS := -std=gnu17 -municode -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -g
COMMON_LDLIBS := -lucrt -lntdll

all: winbindfilterutil.i686.exe winbindfilterutil.x86_64.exe winbindfilterutil.exe

winbindfilterutil.i686.exe: winbindfilterutil.c
	clang -target i686-pc-windows-gnu $(COMMON_CFLAGS) $< $(COMMON_LDLIBS) -o $@
	bash -x -c '"$(SIGNTOOL)" sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

winbindfilterutil.x86_64.exe: winbindfilterutil.c
	clang -target x86_64-pc-windows-gnu $(COMMON_CFLAGS) $< $(COMMON_LDLIBS) -o $@
	bash -x -c '"$(SIGNTOOL)" sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

winbindfilterutil.exe: winbindfilterutil.x86_64.exe
	ln -s winbindfilterutil.x86_64.exe winbindfilterutil.exe

clean:
	rm -fv \
		winbindfilterutil.i686.exe \
		winbindfilterutil.x86_64.exe \
		winbindfilterutil.exe
# EOF.
