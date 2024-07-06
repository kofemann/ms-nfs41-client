#
# /etc/ksh.kshrc+~/.kshrc are sourced only for interactive shells
#

function _ksh_kshrc_is_windows_admin_account
{
	#
	# Test whether we have the Windows permissions to install DLLs
	# and the kernel module
	#
	# Usually Windows Adminstrator rights are indicated by the
	# membership in group "544(Administratoren)" (Cygwin maps
	# "SID S-1-5-32-544" to GID 544)
	#
	if [[ "$(/usr/bin/id -G)" =~ (^|[[:space:]]+)544([[:space:]]+|$) ]] ; then
		return 0
	fi
	return 1
}

# default prompt
if _ksh_kshrc_is_windows_admin_account ; then
	PS1=$'\E[1;91m$(/usr/bin/logname)@$(/usr/bin/hostname) \E[1;33m${PWD/~(Sl-r)$HOME/"~"}\E[0m\n$ '
else
	PS1=$'\E[1;32m$(/usr/bin/logname)@$(/usr/bin/hostname) \E[1;33m${PWD/~(Sl-r)$HOME/"~"}\E[0m\n$ '
fi

# default editor mode
set -o gmacs

# EOF.
