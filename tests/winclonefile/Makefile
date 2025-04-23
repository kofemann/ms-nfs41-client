#
# Makefile for winclonefile
#

# POSIX Makefile

all: winclonefile.i686.exe winclonefile.x86_64.exe winclonefile.exe

winclonefile.i686.exe: winclonefile.c
	clang -target i686-pc-windows-gnu -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -I../../include -g winclonefile.c -lntdll -o winclonefile.i686.exe

winclonefile.x86_64.exe: winclonefile.c
	clang -target x86_64-pc-windows-gnu -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -I../../include -g winclonefile.c -lntdll -o winclonefile.x86_64.exe

winclonefile.exe: winclonefile.x86_64.exe
	ln -s winclonefile.x86_64.exe winclonefile.exe

clean:
	rm -fv \
		winclonefile.i686.exe \
		winclonefile.x86_64.exe \
		winclonefile.exe \
# EOF.
