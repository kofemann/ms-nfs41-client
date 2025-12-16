#
# Makefile for lssparse
#

# signtool.exe can be in either '/cygdrive/c/Program Files/' or '/cygdrive/c/Program Files (x86)/'
SIGNTOOL := $(shell ls -1 '/cygdrive/c/Program Files'*'/Microsoft SDKs/ClickOnce/SignTool/signtool.exe' | head -n 1)

# Cygwin stopped supporting 32bit with Cygwin release 3.3, so no 32bit version
# has SEEK_HOLE/SEEK_DATA support
GETCONF_LONG_BIT := $(strip $(shell getconf LONG_BIT 2>/dev/null || echo 0))

ifeq ($(GETCONF_LONG_BIT),64)
all: lssparse.x86_64.exe lssparse.exe
else
all:
endif

# Cygwin 3.6 does not support 32bit builds anymore
#lssparse.i686.exe: lssparse.c
#	gcc -std=gnu17 -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -I../../include -g lssparse.c -lntdll -o $@
#	bash -x -c '"$(SIGNTOOL)" sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

lssparse.x86_64.exe: lssparse.c
	gcc -std=gnu17 -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -I../../include -g lssparse.c -lntdll -o $@
	bash -x -c '"$(SIGNTOOL)" sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

lssparse.exe: lssparse.x86_64.exe
	ln -s lssparse.x86_64.exe lssparse.exe

clean:
	rm -fv \
		lssparse.x86_64.exe \
		lssparse.exe
# EOF.
