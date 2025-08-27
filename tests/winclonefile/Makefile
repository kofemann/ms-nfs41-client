#
# Makefile for winclonefile
#

# POSIX Makefile
SIGNTOOL="/cygdrive/c/Program Files (x86)/Microsoft SDKs/ClickOnce/SignTool/signtool.exe"

all: winclonefile.i686.exe winclonefile.x86_64.exe winclonefile.exe

winclonefile.i686.exe: winclonefile.c
	clang -target i686-pc-windows-gnu -std=gnu17 -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -I../../include -g winclonefile.c -lntdll -o $@
	bash -x -c '$(SIGNTOOL) sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

winclonefile.x86_64.exe: winclonefile.c
	clang -target x86_64-pc-windows-gnu -std=gnu17 -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -I../../include -g winclonefile.c -lntdll -o $@
	bash -x -c '$(SIGNTOOL) sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

winclonefile.exe: winclonefile.x86_64.exe
	ln -s winclonefile.x86_64.exe winclonefile.exe

clean:
	rm -fv \
		winclonefile.i686.exe \
		winclonefile.x86_64.exe \
		winclonefile.exe
# EOF.
