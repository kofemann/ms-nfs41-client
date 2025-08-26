#
# Makefile for winrunassystem
#

# POSIX Makefile

all: winrunassystem.i686.exe winrunassystem.x86_64.exe winrunassystem.exe

winrunassystem.i686.exe: winrunassystem.c
	clang -target i686-pc-windows-gnu -std=gnu17 -municode -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -g winrunassystem.c -lWtsapi32 -o winrunassystem.i686.exe

winrunassystem.x86_64.exe: winrunassystem.c
	clang -target x86_64-pc-windows-gnu -std=gnu17 -municode -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -g winrunassystem.c -lWtsapi32 -o winrunassystem.x86_64.exe

winrunassystem.exe: winrunassystem.x86_64.exe
	ln -s winrunassystem.x86_64.exe winrunassystem.exe

clean:
	rm -fv \
		winrunassystem.i686.exe \
		winrunassystem.x86_64.exe \
		winrunassystem.exe
# EOF.
