#!/bin/bash

#
# wintartest_seq001.bash - filesystem test
# which generates files with /usr/bin/seq, packs them with
# Cygwin's GNU /usr/bin/tar and tests whether they contain
# zero-bytes (which should never appear in a text file)
# after unpacking them
# with /cygdrive/c/Windows/system32/tar
#
# Written by Roland Mainz <roland.mainz@nrubsig.org>
#

export PATH='/bin:/usr/bin'

typeset -i i
typeset out

set -o xtrace
set -o errexit

# Set umask=0000 to avoid permission trouble with SMB filesystems
umask 0000

rm -f '10000seq.txt'
seq 100000 >'10000seq.txt' ; tar -cvf - '10000seq.txt' >'10000seq.tar' #| pbzip2 -1 >'10000seq.tar.bz2'

rm -Rf 'tmp'
mkdir 'tmp'
cd 'tmp'

set +o xtrace

for (( i=0 ; i < 2000 ; i++ )) ; do
	printf '# Cycle %d:\n' "$i"
	/cygdrive/c/Windows/system32/tar -xvf "$(cygpath -w '../10000seq.tar')"
	out="$(od -x -v '10000seq.txt' | grep -F ' 0000' | head -n 5)"

	if [[ "$out" != '' ]] ; then
		printf '# ERROR: Sequence of zero bytes in plain /usr/bin/seq output found:\n'
		printf -- '---- snip ----\n%s\n---- snip ----\n' "$out"
		exit 1
	fi

	rm -f '10000seq.txt'
done

printf '# SUCCESS\n'

exit 0
# EOF.
