#!/bin/ksh93

#
# MIT License
#
# Copyright (c) 2024 Roland Mainz <roland.mainz@nrubsig.org>
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
# mountall_msnfs41client.ksh93 - mount all msnfs41client NFSv4.1
# filesystems listed in /etc/fstab.msnfs41client
#

#
# Written by Roland Mainz <roland.mainz@nrubsig.org>
#


function parse_fstab_data
{
	nameref fstab_entries=$1
	integer currline=0
	typeset leftover
	typeset s

	for ((currline=0 ; ; currline++ )) ; do
		read -r s || break
		# skip empty lines+lines with spaces only
		if [[ "$s" == ~(Elr)[[:space:]]* ]] ; then
			continue
		fi

		IFS=$' \t\n' read -r \
			fs_spec \
			fs_file \
			fs_vfstype \
			fs_mntops \
			fs_freq \
			fs_passno leftover <<<"$s" || break
		if [[ "${fs_spec}" == ~(El)[[:space:]]*# ]] ; then
			continue
		fi
		if [[ $leftover != '' ]] ; then
			print -u2 -f $"%s: Parsing error in line %d\n" "$0" currline
			continue
		fi

		fstab_entries+=(
			fs_spec="$fs_spec"
			fs_file="$fs_file"
			fs_vfstype="$fs_vfstype"
			fs_mntops="$fs_mntops"
			fs_freq="$fs_freq"
			fs_passno="$fs_passno"
		)
	done

	return 0
}

function read_etc_fstab
{
	nameref arr=$1

	if [[ ! -r "$2" ]] ; then
		print -u2 -f $"%s: Cannot open file %q\n" "$0" "$2"
		return 1
	fi

	parse_fstab_data arr <"$2"
	return $?
}

function fstabentries2nfs_mount_lines
{
	nameref arr=$1
	typeset i

	for i in "${!arr[@]}" ; do
		nameref currfstabentry=arr[$i]

		#print -v currfstabentry

		if [[ "${currfstabentry.fs_vfstype}" != 'nfs' ]] ; then
			continue
		fi

		printf 'nfs_mount -o %q %q %q\n' \
			"${currfstabentry.fs_mntops}" \
			"${currfstabentry.fs_file}" \
			"${currfstabentry.fs_spec}"
	done
	return 0
}

function main
{
	set -o errexit
	compound c
	compound -a c.fstab_entries

	# fixme: not implemented yet
	if [[ "$1" == '--nroff' ]] ; then
		return 0
	fi

	printf $"# Start.\n"

	id -a

	read_etc_fstab c.fstab_entries '/etc/fstab.msnfs41client'

	cmdline="${ fstabentries2nfs_mount_lines c.fstab_entries ; }"

	#
	# FIXME: We should wait until nfsd*.exe is
	# running
	#

	set -o xtrace
	source '/dev/stdin' <<<"$cmdline"
	set +o xtrace

	printf $"# Done.\n"
	return 0
}


#
# Main
#

export PATH='/bin:/usr/bin:/sbin:/usr/sbin'
# add dir (usually "/sbin") in front of PATH so we pick-up
# nfs_mount.
PATH="$(dirname "${.sh.file}"):$PATH"
printf '# PATH=%q\n' "$PATH"

builtin basename
builtin dirname
builtin id

main "$@"
exit $?

# EOF.
