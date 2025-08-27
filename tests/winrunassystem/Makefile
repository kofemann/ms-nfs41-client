#
# Makefile for winrunassystem
#

# POSIX Makefile
SIGNTOOL="/cygdrive/c/Program Files (x86)/Microsoft SDKs/ClickOnce/SignTool/signtool.exe"

all: winrunassystem.i686.exe winrunassystem.x86_64.exe winrunassystem.exe

winrunassystem.i686.exe: winrunassystem.c
	clang -target i686-pc-windows-gnu -std=gnu17 -municode -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -g winrunassystem.c -lWtsapi32 -o $@
	bash -x -c '$(SIGNTOOL) sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

winrunassystem.x86_64.exe: winrunassystem.c
	clang -target x86_64-pc-windows-gnu -std=gnu17 -municode -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -g winrunassystem.c -lWtsapi32 -o $@
	bash -x -c '$(SIGNTOOL) sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

winrunassystem.exe: winrunassystem.x86_64.exe
	ln -s winrunassystem.x86_64.exe $@

clean:
	rm -fv \
		winrunassystem.i686.exe \
		winrunassystem.x86_64.exe \
		winrunassystem.exe
# EOF.
