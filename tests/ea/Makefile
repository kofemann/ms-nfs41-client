#
# Makefile for nfs_ea
#

# POSIX Makefile

all: nfs_ea.i686.exe nfs_ea.x86_64.exe nfs_ea.exe

nfs_ea.i686.exe: main.c
	clang -target i686-pc-windows-gnu -std=gnu17 -municode -Wall -Wextra -D_CRT_STDIO_ISO_WIDE_SPECIFIERS=1 -DUNICODE=1 -D_UNICODE=1 -isystem /usr/include/w32api/ddk -I../../include -g main.c -lntdll -o nfs_ea.i686.exe

nfs_ea.x86_64.exe: main.c
	clang -target x86_64-pc-windows-gnu -std=gnu17 -municode -Wall -Wextra -D_CRT_STDIO_ISO_WIDE_SPECIFIERS=1 -DUNICODE=1 -D_UNICODE=1 -isystem /usr/include/w32api/ddk -I../../include -g main.c -lntdll -o nfs_ea.x86_64.exe

nfs_ea.exe: nfs_ea.x86_64.exe
	rm -f nfs_ea.exe
	ln -s nfs_ea.x86_64.exe nfs_ea.exe

clean:
	rm -fv \
		nfs_ea.i686.exe \
		nfs_ea.x86_64.exe \
		nfs_ea.exe
# EOF.
