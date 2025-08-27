#!/bin/ksh93

# ksh93 scripts using AST getopts(1) support --nroff,
# but we do not do that yet
[[ "$1" == '--nroff' ]] && exit 1

function is_windows_admin_account
{
	#
	# Test whether we have the Windows permissions to install DLLs
	# and the kernel module
	#
	# Usually Windows Adminstrator rights are indicated by the
	# membership in group "544(Administratoren)" (Cygwin maps
	# "SID S-1-5-32-544" to GID 544)
	#
	if [[ "$(/bin/id -G)" =~ (^|[[:space:]]+)544([[:space:]]+|$) ]] ; then
		return 0
	fi
	return 1
}

if ! is_windows_admin_account ; then
	printf $"%s: Requires Windows Adminstator permissions.\n" "$0"
	exit 1
fi

/sbin/winrunassystem "$(cygpath -w '/sbin/nfs_mount.exe')" "$@"
exit $?
# EOF.
