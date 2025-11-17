#
# Makefile for lssparse
#

# signtool.exe can be in either '/cygdrive/c/Program Files/' or '/cygdrive/c/Program Files (x86)/'
SIGNTOOL := $(shell ls -1 '/cygdrive/c/Program Files'*'/Microsoft SDKs/ClickOnce/SignTool/signtool.exe' | head -n 1)

all: lssparse.x86_64.exe lssparse.exe

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
