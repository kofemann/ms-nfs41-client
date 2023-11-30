#!/bin/bash

#
# msnfs41client.bash - simple Cygwin frontent for the msnfsv41
# NFSv4.1 filesystem driver development
#

#
# Written by Roland Mainz <roland.mainz@nrubsig.org>
#

#
# Examples:
#
# 1. Mount for current users:
# (requires PsExec from https://download.sysinternals.com/files/PSTools.zip
# in /home/roland_mainz/work/win_pstools/)
# * Usage:
# Shell1: cd /cygdrive/c/Users/roland_mainz/Downloads/ms-nfs41-client-x64/ms-nfs41-client-x64 && bash ../msnfs41client.bash run_deamon
# Shell2: cd /cygdrive/c/Users/roland_mainz/Downloads/ms-nfs41-client-x64/ms-nfs41-client-x64 && bash ../msnfs41client.bash mount_homedir
#
# 2. Mount for all users:
# * Requires:
# - Windows admin rights (Cygwin --> Run terminal as Adminstrator)
# - PsExec from https://download.sysinternals.com/files/PSTools.zip in /home/roland_mainz/work/win_pstools/)
# * Usage:
# Shell1: cd /cygdrive/c/Users/roland_mainz/Downloads/ms-nfs41-client-x64/ms-nfs41-client-x64 && bash ../msnfs41client.bash sys_run_deamon
# Shell2: cd /cygdrive/c/Users/roland_mainz/Downloads/ms-nfs41-client-x64/ms-nfs41-client-x64 && bash ../msnfs41client.bash sys_mount_homedir
#

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
	if [[ "$(id -G)" =~ (^|[[:space:]]+)544([[:space:]]+|$) ]] ; then
		return 0
	fi
	return 1
}

function nfsclient_install
{
	set -o nounset
	set -o xtrace
	set -o errexit

	if ! is_windows_admin_account ; then
		printf $"%s: Install requires Windows Adminstator permissions.\n" "$0"
		return 1
	fi

	# make sure all binaries are executable, Windows cmd does
	# not care, but Cygwin&bash do.
	# If *.ddl are not executable nfs*.exe fail with 0xc0000022
	chmod a+x *.exe *.dll

	if false ; then
		# install.bat needs PATH to include $PWD
		PATH="$PWD:$PATH" cmd /c install.bat
	else
		# devel: set default in case "nfs_install" ruined it:
		#regtool -s set '/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/NetworkProvider/Order/ProviderOrder' 'RDPNP,LanmanWorkstation,webclient'

		printf 'before nfs_install: ProviderOrder="%s"\n' "$( strings -a '/proc/registry/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/NetworkProvider/Order/ProviderOrder')"
		nfs_install
		printf 'after nfs_install:  ProviderOrder="%s"\n' "$( strings -a '/proc/registry/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/NetworkProvider/Order/ProviderOrder')"

		rundll32 setupapi.dll,InstallHinfSection DefaultInstall 132 ./nfs41rdr.inf
	fi

	mkdir -p /cygdrive/c/etc
	cp etc_netconfig /cygdrive/c/etc/netconfig
	cp ms-nfs41-idmap.conf /cygdrive/c/etc/.

	# enable symlink lookup
	# and then print the status
	fsutil behavior set SymlinkEvaluation L2L:1 R2R:1 L2R:1 R2L:1
	fsutil behavior query SymlinkEvaluation

	# make sure we can load the kernel driver
	# (does not work with SecureBoot)
	bcdedit /set testsigning on

	# enable local kernel debugging
	bcdedit /debug on
	bcdedit /dbgsettings local

	# set domain name
	regtool -s set '/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/Tcpip/Parameters/Domain' 'GLOBAL.LOC'

	# disable DFS
	sc query Dfsc
	sc stop Dfsc || true
	sc config Dfsc start=disabled

	sc query nfs41_driver
	domainname

	openfiles /local ON

	# check whether the driver really has been installed
	md5sum \
		"$PWD/nfs41_driver.sys" \
		'/cygdrive/c/Windows/System32/drivers/nfs41_driver.sys'

	sync

	return 0
}

function nfsclient_rundeamon
{
	set -o xtrace
	set -o nounset

	typeset -a nfsd_args=(
		'nfsd_debug.exe'
		'-d' '0'
		'--noldap'
		#'--numworkerthreads' '512'
		#'--gid' '1616' '--uid' '1616'
	)

	#
	# cdb cheat sheet:
	#
	# gdb: run  cdb: g
	# gdb: bt   cdb: kp
	# gdb: quit cdb: q
	#
	# other useful commands:
	# .lines -e	# enable source code line numbers
	# ~*kp		# print stack traces of all threads
	#

	if false ; then
		nfsd_args=(
			'gdb'
			'-ex=run'
			'--args'
			"${nfsd_args[@]}"
		)
		"${nfsd_args[@]}"
	elif false ; then
		export _NT_ALT_SYMBOL_PATH="$(cygpath -w "$PWD");srv*https://msdl.microsoft.com/download/symbols"
		# use '!gflag +full;g' for heap tests, eats lots of memory
		nfsd_args=(
			'cdb'
			'-c' '!gflag +soe;sxe -c "kp;gn" *;.lines -e;g'
			"$(cygpath -w "$PWD/${nfsd_args[0]}")"
			"${nfsd_args[@]:1}"
		)
		"${nfsd_args[@]}"
	elif false ; then
		#
		# test nfsd_debug.exe with Dr. Memory (version 2.6.0 -- build 0)
		#
		export _NT_ALT_SYMBOL_PATH="$(cygpath -w "$PWD")"
		nfsd_args=(
			'drmemory.exe' \
				'-batch'
				'-brief'
				'-no_follow_children'
				'-lib_blocklist_frames' '1'
				'-check_uninit_blocklist' 'MSWSOCK,WS2_32'
				'-malloc_callstacks'
				'-delay_frees' '16384'
				'-delay_frees_maxsz' $((64*1024*1024))
				'-redzone_size' '4096'
				'-check_uninitialized'
				'-check_uninit_all'
				'-strict_bitops'
				'-gen_suppress_syms'
				'-preload_symbols'
				'--'
				"${nfsd_args[@]}"
			)
		"${nfsd_args[@]}"
	else
		"${nfsd_args[@]}"
	fi
	return $?
}

function nfsclient_system_rundeamon
{
	set -o xtrace
	set -o nounset

	typeset -a nfsd_args=(
		'nfsd_debug.exe'
		'-d' '0'
		'--noldap'
		#'--numworkerthreads' '512'
		#'--gid' '1616' '--uid' '1616'
	)

	# run everything as su_system
	nfsd_args=(
		'su_system'
		"${nfsd_args[@]}"
	)

	#
	# cdb cheat sheet:
	#
	# gdb: run  cdb: g
	# gdb: bt   cdb: kp
	# gdb: quit cdb: q
	#
	# other useful commands:
	# .lines -e	# enable source code line numbers
	# ~*kp		# print stack traces of all threads
	#

	if false ; then
		nfsd_args=(
			'gdb'
			'-ex=run'
			'--args'
			"${nfsd_args[@]}"
		)
		"${nfsd_args[@]}"
	elif false ; then
		export _NT_ALT_SYMBOL_PATH="$(cygpath -w "$PWD");srv*https://msdl.microsoft.com/download/symbols"
		# use '!gflag +full;g' for heap tests, eats lots of memory
		nfsd_args=(
			'cdb'
			'-c' '!gflag +soe;sxe -c "kp;gn" *;.lines -e;g'
			"$(cygpath -w "$PWD/${nfsd_args[0]}")"
			"${nfsd_args[@]:1}"
		)
		"${nfsd_args[@]}"
	elif false ; then
		#
		# test nfsd_debug.exe with Dr. Memory (version 2.6.0 -- build 0)
		#
		export _NT_ALT_SYMBOL_PATH="$(cygpath -w "$PWD")"
		nfsd_args=(
			'drmemory.exe' \
				'-batch'
				'-brief'
				'-no_follow_children'
				'-lib_blocklist_frames' '1'
				'-check_uninit_blocklist' 'MSWSOCK,WS2_32'
				'-malloc_callstacks'
				'-delay_frees' '16384'
				'-delay_frees_maxsz' $((64*1024*1024))
				'-redzone_size' '4096'
				'-check_uninitialized'
				'-check_uninit_all'
				'-strict_bitops'
				'-gen_suppress_syms'
				'-preload_symbols'
				'--'
				"${nfsd_args[@]}"
			)
		"${nfsd_args[@]}"
	else
		"${nfsd_args[@]}"
	fi
	return $?
}

function watch_kernel_debuglog
{
	printf "# logging start...\n" 1>&2
	# seperate process so SIGINT works
	# use DebugView (https://learn.microsoft.com/en-gb/sysinternals/downloads/debugview) to print kernel log
	bash -c '
		klogname="msnfs41client_watch_kernel_debuglog$$.log"
		dbgview64 /t /k /l "$klogname" &
		(( dbgview_pid=$! ))
		trap "(( dbgview_pid != 0)) && kill $dbgview_pid && wait ; (( dbgview_pid=0 ))" INT TERM EXIT
		sleep 2
		printf "# logging %s ...\n" "$klogname" 1>&2
		tail -n0 -f "$klogname"'
	printf "# logging done\n" 1>&2
	return 0
}

function nfsclient_mount_homedir
{
	set -o xtrace
	set -o nounset
	set -o errexit

	#nfs_mount -p -o sec=sys H 'derfwpc5131:/export/home/rmainz'
	# fixme: Specifying IPv6 addresses do not work yet, as soon as
	# they come as UNC paths (e.g.
	# $ cd '//[fe80::219:99ff:feae:73ce]@2049/nfs4/export/home/rmainz' #
	# they get corrupted once they arrive in nfsd_debug.exe)
	#nfs_mount -p -o sec=sys H '[fe80::219:99ff:feae:73ce]:/export/home/rmainz'
	nfs_mount -p -o sec=sys H 'derfwpc5131_ipv6:/export/home/rmainz'
	mkdir -p '/home/rmainz'
	mount -o bind,posix=1 '/cygdrive/h' '/home/rmainz'
	return $?
}

function nfsclient_system_mount_homedir
{
	set -o xtrace
	set -o nounset
	set -o errexit

	# purge any leftover persistent mappings to device H:
	su_system net use H: /delete || true

	#su_system nfs_mount -p -o sec=sys H 'derfwpc5131:/export/home/rmainz'
	# fixme: Specifying IPv6 addresses do not work yet, as soon as
	# they come as UNC paths (e.g.
	# $ cd '//[fe80::219:99ff:feae:73ce]@2049/nfs4/export/home/rmainz' #
	# they get corrupted once they arrive in nfsd_debug.exe)
	#su_system nfs_mount -p -o sec=sys H '[fe80::219:99ff:feae:73ce]:/export/home/rmainz'
	su_system nfs_mount -p -o sec=sys H 'derfwpc5131_ipv6:/export/home/rmainz'

	return $?
}

function nfsclient_umount_homedir
{
	set -o xtrace
	set -o nounset
	typeset -i res

	nfs_mount -d H
	(( res=$? ))

	if (( res == 0 )) ; then
		# remove bind mount
		umount '/home/rmainz' && rmdir '/home/rmainz'
	fi

	return $res
}

function require_cmd
{
	typeset cmd="$1"

	if ! which "$cmd" >'/dev/null' 2>&1 ; then
		printf $"%s: %q not found in %q\n" "$0" "$cmd" "$PWD" 1>&2
		return 1
	fi
	return 0
}

# execute cmd as Windows user "SYSTEM"
function su_system
{
	typeset cmd="$1"
	shift

	typeset abspath_cmd="$(which "$cmd")"
	if [[ ! -x "$abspath_cmd" ]] ; then
		printf "%s: Command %q not found." $"su_system" "$abspath_cmd" 1>&2
		return 127
	fi

	PsExec \
		-accepteula -nobanner \
		-s \
		-w "$(cygpath -w "$PWD")" \
		"$(cygpath -w "$abspath_cmd")" "$@"
}

function sys_terminal
{
	# su_system does not work, mintty requires PsExec -i
	PsExec -accepteula -nobanner \
		-i \
		-s -w "$(cygpath -w "$PWD")" \
		'C:\cygwin64\bin\mintty.exe'
}

function main
{
	typeset cmd="$1"

	# "$PATH:/usr/bin:/bin" is used for PsExec where $PATH might be empty
	export PATH="$PWD:$PATH:/usr/bin:/bin"

	# path to WinDBG cdb (fixme: 64bit x86-specific)
	PATH+=':/cygdrive/c/Program Files (x86)/Windows Kits/10/Debuggers/x64/'

	# my own path to pstools
	PATH+=':/home/roland_mainz/work/win_pstools/'

	# my own path to DebugView
	PATH+=':/cygdrive/c/Users/roland_mainz/download/DebugView'

	case "$cmd" in
		'install')
			nfsclient_install
			return $?
			;;
		'run_deamon' | 'run_daemon')
			require_cmd 'cdb.exe' || return 1
			require_cmd 'nfsd.exe' || return 1
			require_cmd 'nfsd_debug.exe' || return 1
			require_cmd 'nfs_mount.exe' || return 1
			nfsclient_rundeamon
			return $?
			;;
		'sys_run_deamon' | 'sys_run_daemon')
			require_cmd 'cdb.exe' || return 1
			require_cmd 'PsExec.exe' || return 1
			require_cmd 'nfsd.exe' || return 1
			require_cmd 'nfsd_debug.exe' || return 1
			require_cmd 'nfs_mount.exe' || return 1
			if ! is_windows_admin_account ; then
				printf $"%s: %q requires Windows Adminstator permissions.\n" "$0" "$cmd"
				return 1
			fi
			nfsclient_system_rundeamon
			return $?
			;;
		'sys_mount_homedir')
			require_cmd 'nfs_mount.exe' || return 1
			if ! is_windows_admin_account ; then
				printf $"%s: %q requires Windows Adminstator permissions.\n" "$0" "$cmd"
				return 1
			fi
			nfsclient_system_mount_homedir
			return $?
			;;
		'mount_homedir')
			require_cmd 'nfs_mount.exe' || return 1
			nfsclient_mount_homedir
			return $?
			;;
		'umount_homedir')
			require_cmd 'nfs_mount.exe' || return 1
			nfsclient_umount_homedir
			return $?
			;;
		# misc
		'watch_kernel_debuglog')
			require_cmd 'dbgview64' || return 1
			if ! is_windows_admin_account ; then
				printf $"%s: %q requires Windows Adminstator permissions.\n" "$0" "$cmd"
				return 1
			fi
			watch_kernel_debuglog
			return $?
			;;
		'sys_terminal')
			require_cmd 'mintty.exe' || return 1
			if ! is_windows_admin_account ; then
				printf $"%s: %q requires Windows Adminstator permissions.\n" "$0" "$cmd"
				return 1
			fi
			sys_terminal
			return $?
			;;
		*)
			printf $"%s: Unknown cmd %q\n" "$0" "$cmd" 1>&2
			return 1
			;;
	esac
	return 1
}


#
# main
#
main "$@"
exit $?

# EOF.
