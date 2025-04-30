#!/usr/bin/ksh93

#
# MIT License
#
# Copyright (c) 2023-2025 Roland Mainz <roland.mainz@nrubsig.org>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

#
# winlocktest1 - test whether Win32 locks work across NFSv4 mounts
#
# Written by Roland Mainz <roland.mainz@nrubsig.org>
#

#
# Usage:
# 1. modify NFSv4 server location+mount path
# 2. run
# 3. should print "#### Test OK ####"
#

function pw2u
{
	printf '%s\n' "$(cygpath -w "$1")"
}

function cygdrive_nfs_mount_dir
{
	typeset hostname=$2
	typeset mountpath=$3
	nameref mntpoint=$1
	integer retval=0

	#nfs_mount -p -o sec=sys T "derfwnb4966_ipv6:/net_tmpfs2"

	stdout="${ nfs_mount -o sec=sys '*' "${hostname}:${mountpath}" ; (( retval=$? )) ;}"
	#cat <<<"$stdout"

	if (( retval == 0 )) ; then
		# Parse stdout for drive letter
		dummy="${stdout/~(E)Successfully mounted (.+) to drive (?:\'|)(.+):(?:\'|)/dummy}"

		# fixme: we should test whether c.windows_drive_letter is empty or not
		windows_drive_letter="${.sh.match[2]}"

		mntpoint="/cygdrive/$windows_drive_letter/"
		return 0
	fi

	return 1
}

function cygdrive_nfs_umount_dir
{
	typeset mntpath="$1"

	net use "${mntpath/~(Elr)\/cygdrive\/(.)(\/.*|)/\1}:" /delete || true
}

function compile_test_programm
{
	rm -f 'tmp_winlocktest1.c'
	cat >'tmp_winlocktest1.c' <<EOF
/*
 * compile with
 * $ gcc -g -Wall winlocktest1.c -o winlocktest1
 */

#define UNICODE 1

#include <windows.h>
#include <stdio.h>

int main(int ac, char *av[])
{
	OVERLAPPED ovl = { 0 };
	const char *taskname;
	const char *filename;
	const char *text_to_write;
	int sleep_before_lock;
	int sleep_while_lock_held;

	if (ac != 6) {
		(void)fprintf(stderr, "%s: Usage: "
			"%s "
			"<taskname> "
			"<filename> "
			"<text-to-write> "
			"<sec-to-sleep-before-lock> "
			"<sec-to-sleep-while-lock-is-held>\n",
			av[0], av[0]);
		return 1;
	}

	taskname = av[1];
	filename = av[2];
	text_to_write = av[3];
	sleep_before_lock = atoi(av[4]);
	sleep_while_lock_held = atoi(av[5]);

	(void)printf("# %s: start\n", taskname);

	// Open the file for read and write access.
	HANDLE hFile = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		perror("Error opening file.\n");
		return 1;
	}

	(void)printf("# %s: sleeping\n", taskname);
	Sleep(sleep_before_lock*1000);

	(void)printf("# %s: before lock\n", taskname);
	// Lock the file from offset 10 to offset 20.
	if (LockFileEx(hFile, LOCKFILE_EXCLUSIVE_LOCK, 0, 10, 20, &ovl) == 0) {
		fprintf(stderr, "Error locking file.\n");
		CloseHandle(hFile);
		return 1;
	}
	(void)printf("# %s: file locked\n", taskname);

	Sleep(sleep_while_lock_held*1000);

	// Perform some operations on the locked region of the file.
	DWORD bytesWritten;
	if (WriteFile(hFile, text_to_write, strlen(text_to_write), &bytesWritten, NULL) == 0) {
		fprintf(stderr, "Error writing to file.\n");
		UnlockFileEx(hFile, 0, 10, 20, &ovl);
		CloseHandle(hFile);
		return 1;
	}

	// Unlock the file.
	if (UnlockFileEx(hFile, 0, 10, 20, &ovl) == 0) {
		fprintf(stderr, "Error unlocking file.\n");
		CloseHandle(hFile);
		return 1;
	}
	(void)printf("# %s: file unlocked\n", taskname);

	// Close the file.
	CloseHandle(hFile);
	(void)printf("# %s: done\n", taskname);

	return 0;
}
EOF
	rm -f winlocktest1.exe
	gcc -g -Wall tmp_winlocktest1.c -o winlocktest1.exe
}

#
# main
#
set -o xtrace
set -o errexit
set -o nounset

PATH+=':/home/roland_mainz/work/msnfs41_uidmapping/ms-nfs41-client/destdir/cygdrive/c/cygwin64/sbin/'


# td==testdata
compound td

td.hostname="derfwnb4966_ipv6"
td.mntpoint="/net_tmpfs2"

compile_test_programm || exit 1

cygdrive_nfs_mount_dir td.basedir "${td.hostname}" "${td.mntpoint}" || exit 1

mkdir -p "${td.basedir}/lockdir2/test1"

cygdrive_nfs_mount_dir td.dir1 "${td.hostname}" "${td.mntpoint}/lockdir2" || exit 1
td.dir1+="/test1"
cygdrive_nfs_mount_dir td.dir2 "${td.hostname}" "${td.mntpoint}/lockdir2/test1" || exit 1

print -v td

printf 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n' >"${td.dir1}/example.txt"


./winlocktest1.exe "T1" "$(pw2u "${td.dir1}/example.txt")" ".......... test 12345" 1 12 &
./winlocktest1.exe "T2" "$(pw2u "${td.dir2}/example.txt")" ".......... test ABCDE" 4 1 &
sleep 2

# this should fail, because T1 has locked "${td.dir1}/example.txt"
if [[ "$( { cat "${td.dir1}/example.txt" || true ; } 2>&1)" == *busy* ]] ; then
	print OK
fi
# this should fail, because T1 has locked "${td.dir1}/example.txt"
if [[ "$( { cat "${td.dir2}/example.txt" || true ; } 2>&1)" == *busy* ]] ; then
	print OK
fi

wait
cat -n "${td.dir1}/example.txt"
cat -n "${td.dir2}/example.txt"

#
# cleanup - must be successful, no leftover files
#
rm "${td.basedir}/lockdir2/test1/example.txt"
rmdir "${td.basedir}/lockdir2/test1"
rmdir "${td.basedir}/lockdir2"

#
# unmount test dirs
#
cygdrive_nfs_umount_dir "${td.dir2}" || true
cygdrive_nfs_umount_dir "${td.dir1}" || true
cygdrive_nfs_umount_dir "${td.basedir}" || true

print "#### Test OK ####"

# EOF.
