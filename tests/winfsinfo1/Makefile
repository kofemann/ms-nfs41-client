#
# Makefile for winfsinfo
#

# POSIX Makefile

winfsinfo: winfsinfo.c
	gcc -Wall -DUNICODE=1 -D_UNICODE=1 -g winfsinfo.c -o winfsinfo

all: winfsinfo

clean:
	rm -fv \
		winfsinfo.exe
# EOF.
