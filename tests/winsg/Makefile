#
# Makefile for winsg
#

# POSIX Makefile

all: winsg.i686.exe winsg.x86_64.exe winsg.exe

winsg.i686.exe: winsg.c
	clang -target i686-pc-windows-gnu -Wall -DUNICODE=1 -D_UNICODE=1 -g winsg.c -o winsg.i686.exe

winsg.x86_64.exe: winsg.c
	clang -target x86_64-pc-windows-gnu -Wall -DUNICODE=1 -D_UNICODE=1 -g winsg.c -o winsg.x86_64.exe

winsg.exe: winsg.x86_64.exe
	ln -s winsg.x86_64.exe winsg.exe

clean:
	rm -fv \
		winsg.i686.exe \
		winsg.x86_64.exe \
		winsg.exe
# EOF.
