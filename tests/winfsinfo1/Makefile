#
# Makefile for winfsinfo
#

# POSIX Makefile

all: winfsinfo.i686.exe winfsinfo.x86_64.exe winfsinfo.exe

winfsinfo.i686.exe: winfsinfo.c
	clang -target i686-pc-windows-gnu -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -I../../include -g winfsinfo.c -lntdll -o winfsinfo.i686.exe

winfsinfo.x86_64.exe: winfsinfo.c
	clang -target x86_64-pc-windows-gnu -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -I../../include -g winfsinfo.c -lntdll -o winfsinfo.x86_64.exe

winfsinfo.exe: winfsinfo.x86_64.exe
	ln -s winfsinfo.x86_64.exe winfsinfo.exe

clean:
	rm -fv \
		winfsinfo.i686.exe \
		winfsinfo.x86_64.exe \
		winfsinfo.exe
# EOF.
