#
# Makefile for qsortonmmapedfile1
#

# POSIX Makefile
SIGNTOOL="/cygdrive/c/Program Files (x86)/Microsoft SDKs/ClickOnce/SignTool/signtool.exe"

all: \
	qsortonmmapedfile1.i686.exe \
	qsortonmmapedfile1.x86_64.exe \
	qsortonmmapedfile1.exe

qsortonmmapedfile1.i686.exe: qsortonmmapedfile1.c
	clang -target i686-pc-windows-gnu -std=gnu17 -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -g -O qsortonmmapedfile1.c -o $@
	bash -x -c '$(SIGNTOOL) sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

qsortonmmapedfile1.x86_64.exe: qsortonmmapedfile1.c
	clang -target x86_64-pc-windows-gnu -std=gnu17 -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -g -O qsortonmmapedfile1.c -o $@
	bash -x -c '$(SIGNTOOL) sign /ph /fd "sha256" /sha1 "$${CERTIFICATE_THUMBPRINT%$$(printf "\r")}" $@'

qsortonmmapedfile1.exe: qsortonmmapedfile1.x86_64.exe
	ln -s qsortonmmapedfile1.x86_64.exe qsortonmmapedfile1.exe

clean:
	rm -fv \
		qsortonmmapedfile1.i686.exe \
		qsortonmmapedfile1.x86_64.exe \
		qsortonmmapedfile1.exe
# EOF.
