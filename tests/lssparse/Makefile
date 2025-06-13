#
# Makefile for lssparse
#

# POSIX Makefile

all: lssparse.x86_64.exe lssparse.exe

# Cygwin 3.6 does not support 32bit builds anymore
#lssparse.i686.exe: lssparse.c
#	gcc -std=gnu17 -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -I../../include -g lssparse.c -lntdll -o lssparse.i686.exe

lssparse.x86_64.exe: lssparse.c
	gcc -std=gnu17 -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -I../../include -g lssparse.c -lntdll -o lssparse.x86_64.exe

lssparse.exe: lssparse.x86_64.exe
	ln -s lssparse.x86_64.exe lssparse.exe

clean:
	rm -fv \
		lssparse.x86_64.exe \
		lssparse.exe
# EOF.
