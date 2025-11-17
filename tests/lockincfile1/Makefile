#
# Makefile for lockincfile1
#

# signtool.exe can be in either '/cygdrive/c/Program Files/' or '/cygdrive/c/Program Files (x86)/'
SIGNTOOL := $(shell ls -1 '/cygdrive/c/Program Files'*'/Microsoft SDKs/ClickOnce/SignTool/signtool.exe' | head -n 1)

all: \
	lockincfile1.i686.exe \
	lockincfile1.x86_64.exe \
	lockincfile1.exe

lockincfile1.i686.exe: lockincfile1.c
	clang -target i686-pc-windows-gnu -std=gnu17 -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -g -O lockincfile1.c -o $@
	bash -x -c '"$(SIGNTOOL)" sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

lockincfile1.x86_64.exe: lockincfile1.c
	clang -target x86_64-pc-windows-gnu -std=gnu17 -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -g -O lockincfile1.c -o $@
	bash -x -c '"$(SIGNTOOL)" sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

lockincfile1.exe: lockincfile1.x86_64.exe
	ln -s lockincfile1.x86_64.exe lockincfile1.exe

clean:
	rm -fv \
		lockincfile1.i686.exe \
		lockincfile1.x86_64.exe \
		lockincfile1.exe
# EOF.
