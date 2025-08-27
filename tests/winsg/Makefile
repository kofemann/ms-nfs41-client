#
# Makefile for winsg
#

# POSIX Makefile
SIGNTOOL="/cygdrive/c/Program Files (x86)/Microsoft SDKs/ClickOnce/SignTool/signtool.exe"

all: winsg.i686.exe winsg.x86_64.exe winsg.exe

winsg.i686.exe: winsg.c
	clang -target i686-pc-windows-gnu -std=gnu17 -municode -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -g winsg.c -o $@
	bash -x -c '$(SIGNTOOL) sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

winsg.x86_64.exe: winsg.c
	clang -target x86_64-pc-windows-gnu -std=gnu17 -municode -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -g winsg.c -o $@
	bash -x -c '$(SIGNTOOL) sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

winsg.exe: winsg.x86_64.exe
	ln -s winsg.x86_64.exe winsg.exe

clean:
	rm -fv \
		winsg.i686.exe \
		winsg.x86_64.exe \
		winsg.exe
# EOF.
