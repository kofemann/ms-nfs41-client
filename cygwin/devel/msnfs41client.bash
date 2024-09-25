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
# Shell2: cd /cygdrive/c/Users/roland_mainz/Downloads/ms-nfs41-client-x64/ms-nfs41-client-x64 && bash ../msnfs41client.bash sys_mount_globaldirs
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

function check_machine_arch
{
	typeset winpwd
	typeset uname_m

	# get the location where this script is installed,
	# because on Cygwin the script will be installed
	# in /cygdrive/c/cygwin/lib/msnfs41client/ (32bit) or
	# in /cygdrive/c/cygwin64/lib/msnfs41client/ (64bit).
	winpwd="$(cygpath -w "$(dirname -- "$(realpath "${BASH_SOURCE[0]}")")")"

	uname_m="$(uname -m)"

	case "${uname_m}" in
		'x86_64')
			if [[ "${winpwd}" != 'C:\cygwin64\'* ]] ; then
				printf $"%s: Requires 64bit Cygwin\n" "$0" 1>&2
				return 1
			fi
			return 0
			;;
		'i686')
			if [[ "${winpwd}" != 'C:\cygwin\'* ]] ; then
				printf $"%s: Requires 32bit Cygwin\n" "$0" 1>&2
				return 1
			fi
			return 0
			;;
		*)
			printf $"%s: Unknown arch/Cygwin combination ('%s'/'%s')\n" "$0" "${uname_m}" "${winpwd}" 1>&2
			return 1
			;;
	esac
	# not reached
}

function nfsclient_install
{
	set -o nounset
	set -o xtrace
	set -o errexit

	# switch to the location where this script is installed,
	# because on Cygwin the script will be installed
	# in /cygdrive/c/cygwin/lib/msnfs41client/ (32bit) or
	# in /cygdrive/c/cygwin64/lib/msnfs41client/ (64bit).
	cd -P "$(dirname -- "$(realpath "${BASH_SOURCE[0]}")")"

	# make sure all binaries are executable, Windows cmd does
	# not care, but Cygwin&bash do.
	# If *.ddl are not executable nfs*.exe fail with 0xc0000022
	chmod a+x *.dll
	chmod a+x ../../sbin/nfs*.exe ../../sbin/libtirpc*.dll

	# (re-)install driver
	nfsclient_adddriver

	mkdir -p /cygdrive/c/etc
	cp etc_netconfig /cygdrive/c/etc/netconfig
	cp ms-nfs41-idmap.conf /cygdrive/c/etc/.

	# enable symlink lookup
	# and then print the status
	fsutil behavior set SymlinkEvaluation L2L:1 R2R:1 L2R:1 R2L:1
	fsutil behavior query SymlinkEvaluation

	# enable Win32 long paths
	# (see https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation)
	regtool -i set '/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/FileSystem/LongPathsEnabled' 1
	od -t x4 <'/proc/registry/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/FileSystem/LongPathsEnabled'

	# use the Win10 "SegmentHeap" (see https://www.blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals.pdf)
	regtool add '/HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Image File Execution Options/nfsd_debug.exe'
	regtool -i set '/HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Image File Execution Options/nfsd_debug.exe/FrontEndHeapDebugOptions' 0x08
	regtool add '/HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Image File Execution Options/nfsd.exe'
	regtool -i set '/HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Image File Execution Options/nfsd.exe/FrontEndHeapDebugOptions' 0x08
	regtool add '/HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Image File Execution Options/nfs_mount.exe'
	regtool -i set '/HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Image File Execution Options/nfs_mount.exe/FrontEndHeapDebugOptions' 0x08

	# make sure we can load the kernel driver
	# (does not work with SecureBoot)
	bcdedit /set testsigning on

	# enable local kernel debugging
	bcdedit /debug on
	bcdedit /dbgsettings local

	# set domain name
	typeset win_domainname=''
	if [[ -f '/proc/registry/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/Tcpip/Parameters/Domain' ]] ; then
		win_domainname="$( strings '/proc/registry/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/Tcpip/Parameters/Domain' )"
	fi
	if [[ "${win_domainname}" == '' ]] ; then
	regtool -s set '/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/Tcpip/Parameters/Domain' 'GLOBAL.LOC'
	fi

	# disable DFS
	sc query Dfsc
	sc stop Dfsc || true
	sc config Dfsc start=disabled

	sc query nfs41_driver
	domainname

	openfiles /local ON

	#
	# install "msnfs41client run_daemon" as system service
	# 'ms-nfs41-client-service'
	# "off" by default, requires manual starting
	#

	# remove 'ms-nfs41-client-service'
	sc stop 'ms-nfs41-client-service' || true
	cygrunsrv --remove 'ms-nfs41-client-service' || true
	if [[ -f '/var/log/ms-nfs41-client-service.log' ]] ; then
		mv \
			'/var/log/ms-nfs41-client-service.log' \
			"/var/log/ms-nfs41-client-service.log.old$(date +%Y%m%d_%Hh%Mm)"
	fi

	#
	# create new '/var/log/ms-nfs41-client-service.log'
	# so users can do a $ tail -f
	# '/var/log/ms-nfs41-client-service.log' at any time
	#
	touch '/var/log/ms-nfs41-client-service.log'
	chown SYSTEM:SYSTEM '/var/log/ms-nfs41-client-service.log'
	chmod u+w,go-w '/var/log/ms-nfs41-client-service.log'

	# install new 'ms-nfs41-client-service'
	cygrunsrv --install \
		'ms-nfs41-client-service' \
		--path "$PWD/msnfs41client" \
		--args 'run_daemon' \
		--type 'manual' \
		--chdir "$PWD"

	# query new 'ms-nfs41-client-service'
	sc query 'ms-nfs41-client-service'

	#
	# install "mountall_msnfs41client" as system service
	# 'ms-nfs41-client-globalmountall-service'
	# "off" by default, requires manual starting
	#

	# remove 'ms-nfs41-client-globalmountall-service'
	sc stop 'ms-nfs41-client-globalmountall-service' || true
	cygrunsrv --remove 'ms-nfs41-client-globalmountall-service' || true
	if [[ -f '/var/log/ms-nfs41-client-globalmountall-service.log' ]] ; then
		mv \
			'/var/log/ms-nfs41-client-globalmountall-service.log' \
			"/var/log/ms-nfs41-client-globalmountall-service.log.old$(date +%Y%m%d_%Hh%Mm)"
	fi

	#
	# create new '/var/log/ms-nfs41-client-globalmountall-service.log'
	# so users can do a $ tail -f
	# '/var/log/ms-nfs41-client-globalmountall-service.log' at any time
	#
	touch '/var/log/ms-nfs41-client-globalmountall-service.log'
	chown SYSTEM:SYSTEM '/var/log/ms-nfs41-client-globalmountall-service.log'
	chmod u+w,go-w '/var/log/ms-nfs41-client-globalmountall-service.log'

	# install new 'ms-nfs41-client-globalmountall-service'
	cygrunsrv --install \
		'ms-nfs41-client-globalmountall-service' \
		--path "$PWD/msnfs41client" \
		--args 'sys_mount_globaldirs' \
		--type 'manual' \
		--chdir "$PWD"

	# install dummy /etc/fstab.msnfs41client if system does not have one
	if [[ ! -f '/etc/fstab.msnfs41client' ]] ; then
		{
			printf '#\n'
			printf '# /etc/fstab.msnfs41client - used by /sbin/mountall_msnfs41client\n'
			printf '#\n\n'
			printf '# nfs://[fe80::21b:1bff:fec3:7713]//bigdisk\tV\tnfs\trw\t0\t0\n\n'
			printf '# EOF.\n'
		} >'/etc/fstab.msnfs41client'
	fi

	# query new 'ms-nfs41-client-globalmountall-service'
	sc query 'ms-nfs41-client-globalmountall-service'

	#
	# check whether ksh93 works
	# (The ms-nfs41-client cygwin idmapper uses ksh93 scripts for
	# idmapping, and if ksh93 does not work properly nfsd*.exe
	# will not work)
	#
	set +o xtrace
	typeset cmdout
	cmdout="$( \
		{ \
			/usr/bin/ksh93 -c \
				'compound c=(typeset -a ar); c.ar=("hello"); c.ar+=("world"); printf "%s" "${c.ar[*]}"' ; \
			echo $? ; } 2>&1 \
		)"

	if [[ "${cmdout}" != $'hello world0' ]] ; then
		printf $"ERROR: /usr/bin/ksh93 does not work, expected test output |%q|, got |%q|\n" \
			$'hello world0' \
			"$cmdout"
		return 1
	fi
	printf '/usr/bin/ksh93 is working\n'
	set -o xtrace

	# check whether the driver really has been installed
	md5sum \
		"$PWD/nfs41_driver.sys" \
		'/cygdrive/c/Windows/System32/drivers/nfs41_driver.sys'

	sync

	return 0
}

function nfsclient_adddriver
{
	set -o nounset
	set -o xtrace
	set -o errexit

	# switch to the location where this script is installed,
	# because on Cygwin the script will be installed
	# in /cygdrive/c/cygwin/lib/msnfs41client/ (32bit) or
	# in /cygdrive/c/cygwin64/lib/msnfs41client/ (64bit).
	cd -P "$(dirname -- "$(realpath "${BASH_SOURCE[0]}")")"

	# devel: set default in case "nfs_install" ruined it:
	#regtool -s set '/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/NetworkProvider/Order/ProviderOrder' 'RDPNP,LanmanWorkstation,webclient'

	printf 'before nfs_install: ProviderOrder="%s"\n' "$( strings -a '/proc/registry/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/NetworkProvider/Order/ProviderOrder')"
	nfs_install -D
	printf 'after nfs_install:  ProviderOrder="%s"\n' "$( strings -a '/proc/registry/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/NetworkProvider/Order/ProviderOrder')"

	rundll32 setupapi.dll,InstallHinfSection DefaultInstall 132 ./nfs41rdr.inf

	#
	# Hack: Manually Add 32bit provider DLL to a 64bit system, so
	# 32bit applications can enumerate the ms-nfs41-client shares
	# (FIXME: technically nfs41rdr.inf should do this)
	#
	if [[ -d '/cygdrive/c/Windows/SysWOW64/' ]] ; then
		# copy from the 32bit install dir
		cp '../../../../../cygdrive/c/cygwin/lib/msnfs41client/nfs41_np.dll' '/cygdrive/c/Windows/SysWOW64/'
	fi

	return 0
}

function nfsclient_removedriver
{
	set -o nounset
	set -o xtrace
	set -o errexit

	# switch to the location where this script is installed,
	# because on Cygwin the script will be installed
	# in /cygdrive/c/cygwin/lib/msnfs41client/ (32bit) or
	# in /cygdrive/c/cygwin64/lib/msnfs41client/ (64bit).
	cd -P "$(dirname -- "$(realpath "${BASH_SOURCE[0]}")")"

	nfs_install.exe 0
	rundll32.exe setupapi.dll,InstallHinfSection DefaultUninstall 132 ./nfs41rdr.inf
	rm /cygdrive/c/Windows/System32/nfs41_np.dll || true
	if [[ -d '/cygdrive/c/Windows/SysWOW64/' ]] ; then
		rm '/cygdrive/c/Windows/SysWOW64/nfs41_np.dll' || true
	fi
	rm /cygdrive/c/Windows/System32/drivers/nfs41_driver.sys || true

	sync

	return 0
}

function nfsclient_waitfor_clientdaemon
{
	typeset -i i

	#
	# wait for two minutes, and poll in 0.25 second intervals
	# (four times per second)
	#
	for (( i=0 ; i < 120*4 ; i++ )) ; do
		#
		# '/proc/sys/BaseNamedObjects/nfs41_shared_memory' is created
		# when nfsd*.exe starts
		# Note that this file is not removed if nfsd*.exe exits,
		# so we explicitly query tasklist too
		#
		if [[ -e '/proc/sys/BaseNamedObjects/nfs41_shared_memory' ]] ; then
			if [[ "$(tasklist | grep -E 'nfsd(|_debug).exe')" != '' ]] ; then
				break
			fi
		fi

		# print message every 5 seconds
		if (( i%(5*4) == 0 )) ; then
			printf '%s: Waiting for nfsd*.exe to start\n' "$0"
		fi
		sleep 0.25
	done

	if [[ -e '/proc/sys/BaseNamedObjects/nfs41_shared_memory' ]] ; then
		if [[ "$(tasklist | grep -E 'nfsd(|_debug).exe')" != '' ]] ; then
			return 0
		fi
	fi
	return 1
}

function nfsclient_rundeamon
{
	set -o nounset

	printf '# user="%s" uname="%s" isadmin=%d domainname="%s"\n' \
		"$(id -u -n)" \
		"$(uname -a)" \
		"$(is_windows_admin_account ; printf "%d\n" $((${?}?0:1)))" \
		"$(domainname)"

	# sync before starting nfs41 client daemon, to limit the damage
	# if the kernel module generates a crash on startup
	sync

	set -o xtrace

	typeset -a nfsd_args=(
		'nfsd.exe'
		'-debug'
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
		# test nfsd.exe with Dr. Memory (version 2.6.0 -- build 0)
		#
		export _NT_ALT_SYMBOL_PATH="$(cygpath -w "$PWD")"
		nfsd_args=(
			'drmemory.exe' \
				'-batch'
				'-brief'
				'-no_follow_children'
				'-lib_blocklist_frames' '1'
				'-check_uninit_blocklist' 'MSWSOCK,WS2_32,ucrtbased.dll,ucrtbase.dll'
				'-malloc_callstacks'
				'-delay_frees' '16384'
				'-delay_frees_maxsz' $((64*1024*1024))
				'-redzone_size' '4096'
				'-check_uninitialized'
				'-check_uninit_all'
				'-strict_bitops'
				'-gen_suppress_syms'
				'-preload_symbols'
				# no symbol cache, user "SYSTEM" cannot write data to cache
				'-no_use_symcache'
				'--'
				"${nfsd_args[@]}"
				'--crtdbgmem' 'none'
			)

		# Killing DrMemory with <CTRL-C> does not terminate nfsd,
		# so we have to do it ourselves
		trap 'taskkill /F /IM nfsd.exe' SIGINT SIGTERM

		"${nfsd_args[@]}"
	elif false ; then
		typeset -i vsdiagnostics_id=50
		VSDiagnostics \
			start ${vsdiagnostics_id} \
			"/launch:$(cygpath -w "$PWD/nfsd.exe")" \
			"/launchArgs:${nfsd_args[*]:1}" \
			"/loadConfig:$(cygpath -w "${vsdiagnostics_path}/AgentConfigs/CpuUsageHigh.json")"
		printf '#\n'
		printf '# use\n'
		printf '# $ "%s" stop %d /output:nfsd%d # to collect profiling data\n#\n' \
			"$(which -a 'VSDiagnostics.exe')" \
			"${vsdiagnostics_id}" "$$"
	else
		"${nfsd_args[@]}"
	fi
	return $?
}

function nfsclient_system_rundeamon
{
	set -o nounset

	printf '# user="%s" uname="%s" isadmin=%d domainname="%s"\n' \
		"$(id -u -n)" \
		"$(uname -a)" \
		"$(is_windows_admin_account ; printf "%d\n" $((${?}?0:1)))" \
		"$(domainname)"

	# sync before starting nfs41 client daemon, to limit the damage
	# if the kernel module generates a crash on startup
	sync

	set -o xtrace

	typeset -a nfsd_args=(
		'nfsd.exe'
		'-debug'
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

		# run everything as su_system
		nfsd_args=(
			'su_system'
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

		# run everything as su_system
		nfsd_args=(
			'su_system'
			"${nfsd_args[@]}"
		)

		"${nfsd_args[@]}"
	elif false ; then
		#
		# test nfsd.exe with Dr. Memory (version 2.6.0 -- build 0)
		#
		export _NT_ALT_SYMBOL_PATH="$(cygpath -w "$PWD")"
		nfsd_args=(
			'drmemory.exe' \
				'-batch'
				'-brief'
				'-no_follow_children'
				'-lib_blocklist_frames' '1'
				'-check_uninit_blocklist' 'MSWSOCK,WS2_32,ucrtbased.dll,ucrtbase.dll'
				'-malloc_callstacks'
				'-delay_frees' '16384'
				'-delay_frees_maxsz' $((64*1024*1024))
				'-redzone_size' '4096'
				'-check_uninitialized'
				'-check_uninit_all'
				'-strict_bitops'
				'-gen_suppress_syms'
				'-preload_symbols'
				# no symbol cache, user "SYSTEM" cannot write data to cache
				'-no_use_symcache'
				'--'
				"${nfsd_args[@]}"
				'--crtdbgmem' 'none'
			)

		# run everything as su_system
		nfsd_args=(
			'su_system'
			"${nfsd_args[@]}"
		)

		# Killing DrMemory with <CTRL-C> does not terminate nfsd,
		# so we have to do it ourselves
		trap 'taskkill /F /IM nfsd.exe' SIGINT SIGTERM

		"${nfsd_args[@]}"
	elif false ; then
		typeset -i vsdiagnostics_id=50
		# run everything as su_system
		su_system VSDiagnostics \
			start ${vsdiagnostics_id} \
			"/launch:$(cygpath -w "$PWD/nfsd.exe")" \
			"/launchArgs:${nfsd_args[*]:1}" \
			"/loadConfig:$(cygpath -w "${vsdiagnostics_path}/AgentConfigs/CpuUsageHigh.json")"
		printf '#\n'
		printf '# use\n'
		printf '# $ "%s" stop %d /output:nfsd%d # to collect profiling data\n#\n' \
			"$(which -a 'VSDiagnostics.exe')" \
			"${vsdiagnostics_id}" "$$"
	else
		# run everything as su_system
		nfsd_args=(
			'su_system'
			"${nfsd_args[@]}"
		)

		"${nfsd_args[@]}"
	fi
	return $?
}

function watch_kernel_debuglog
{
	typeset dbgview_cmd

	printf "# logging start...\n" 1>&2

	case "$(uname -m)" in
		'x86_64') dbgview_cmd='dbgview64' ;;
		'i686')   dbgview_cmd='dbgview' ;;
		*)
			printf $"%s: Unknown machine type\n" "$0" 1>&2
			return 1
			;;
	esac

	# seperate process so SIGINT works
	# use DebugView (https://learn.microsoft.com/en-gb/sysinternals/downloads/debugview) to print kernel log
	dbgview_cmd="${dbgview_cmd}" bash -c '
		klogname="msnfs41client_watch_kernel_debuglog$$.log"
		$dbgview_cmd /t /k /l "$klogname" &
		(( dbgview_pid=$! ))
		trap "(( dbgview_pid != 0)) && kill $dbgview_pid && wait ; (( dbgview_pid=0 ))" INT TERM EXIT
		sleep 2
		printf "# logging %s ...\n" "$klogname" 1>&2
		tail -n0 -f "$klogname"'
	printf '# logging done\n' 1>&2
	return 0
}

function nfsclient_system_mount_globaldirs
{
	set -o xtrace
	set -o nounset
	set -o errexit

	if ! nfsclient_waitfor_clientdaemon ; then
		print -u2 -f $"%s: nfsd*.exe not running.\n" "$0"
		return 1
	fi

	mountall_msnfs41client

	return $?
}

function nfsclient_system_umount_globaldirs
{
	# fixme: needs to be implemented
	return 1
}

function nfsclient_mount_homedir
{
	set -o xtrace
	set -o nounset
	set -o errexit

	if ! nfsclient_waitfor_clientdaemon ; then
		print -u2 -f $"%s: nfsd*.exe not running.\n" "$0"
		return 1
	fi

	#nfs_mount -p -o sec=sys H 'derfwpc5131:/export/home2/rmainz'
	#nfs_mount -p -o sec=sys H '[fe80::219:99ff:feae:73ce]:/export/home2/rmainz'
	nfs_mount -p -o sec=sys H 'derfwpc5131_ipv6linklocal:/export/home2/rmainz'
	mkdir -p '/home/rmainz'
	# FIXME: is "notexec" correct in this case ?
	mount -o posix=1,sparse,notexec 'H:' '/home/rmainz'
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

function require_file
{
	typeset testfile="$1"

	if [[ ! -f "$testfile" ]] ; then
		printf $"%s: File %q not found in %q\n" "$0" "$cmd" "$PWD" 1>&2
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
		"$(cygpath -w "$(which mintty.exe)")" --nodaemon
}

function main
{
	typeset cmd="$1"
	typeset -i numerr=0

	# path where this script is installed
	typeset scriptpath="$(dirname -- "$(realpath "${BASH_SOURCE[0]}")")"

	# "$PATH:/usr/bin:/bin" is used for PsExec where $PATH might be empty
	PATH="$PWD:$PATH:${scriptpath}../../usr/bin:${scriptpath}/../../bin:${scriptpath}/../../sbin:${scriptpath}/../../usr/sbin"
	# add defauft system path for POSIX utilities
	PATH+=':/sbin:/usr/sbin:/bin:/usr/bin'

	# add Windows tools path (tasklist, taskkill etc.)
	PATH+=':/cygdrive/c/Windows/system32/'

	# path to WinDBG cdb (fixme: 64bit x86-specific)
	PATH+=':/cygdrive/c/Program Files (x86)/Windows Kits/10/Debuggers/x64/'

	# PATH to VSDiagnostics.exe and AgentConfigs
	vsdiagnostics_path='/cygdrive/c/Program Files (x86)/Microsoft Visual Studio/2019/Community/Team Tools/DiagnosticsHub/Collector/'
	PATH+=":${vsdiagnostics_path}"

	# PATH to DrMemory
	PATH+=':/cygdrive/c/Program Files (x86)/Dr. Memory/bin/'

	# my own path to pstools
	PATH+=':/home/roland_mainz/work/win_pstools/'

	# my own path to DebugView
	PATH+=':/cygdrive/c/Users/roland_mainz/download/DebugView'

	case "$cmd" in
		'install')
			check_machine_arch || (( numerr++ ))
			require_cmd 'regtool.exe' || (( numerr++ ))
			require_cmd 'cygrunsrv.exe' || (( numerr++ ))
			require_cmd 'nfsd.exe' || (( numerr++ ))
			require_cmd 'nfs_install.exe' || (( numerr++ ))
			require_cmd 'rundll32.exe' || (( numerr++ ))
			require_cmd 'bcdedit.exe' || (( numerr++ ))
			require_cmd 'fsutil.exe' || (( numerr++ ))
			require_cmd 'sc.exe' || (( numerr++ ))
			if ! is_windows_admin_account ; then
				printf $"%s: %q requires Windows Adminstator permissions.\n" "$0" "$cmd"
				(( numerr++ ))
			fi
			(( numerr > 0 )) && return 1

			nfsclient_install
			return $?
			;;
		#
		# 'removedriver' should only be used by developers,
		# as 'install' can always overwrite an existing driver
		#
		'removedriver')
			check_machine_arch || (( numerr++ ))
			require_cmd 'nfs_install.exe' || (( numerr++ ))
			require_cmd 'rundll32.exe' || (( numerr++ ))
			if ! is_windows_admin_account ; then
				printf $"%s: %q requires Windows Adminstator permissions.\n" "$0" "$cmd"
				(( numerr++ ))
			fi
			(( numerr > 0 )) && return 1

			nfsclient_removedriver
			return $?
			;;
		'run_deamon' | 'run_daemon')
			check_machine_arch || (( numerr++ ))
			#require_cmd 'cdb.exe' || (( numerr++ ))
			require_cmd 'nfsd.exe' || (( numerr++ ))
			require_cmd 'nfsd_debug.exe' || (( numerr++ ))
			require_cmd 'nfs_mount.exe' || (( numerr++ ))
			require_cmd 'ksh93.exe' || (( numerr++ ))
			require_file '/lib/msnfs41client/cygwin_idmapper.ksh' || (( numerr++ ))
			(( numerr > 0 )) && return 1

			nfsclient_rundeamon
			return $?
			;;
		'sys_run_deamon' | 'sys_run_daemon')
			check_machine_arch || (( numerr++ ))
			#require_cmd 'cdb.exe' || (( numerr++ ))
			require_cmd 'PsExec.exe' || (( numerr++ ))
			require_cmd 'nfsd.exe' || (( numerr++ ))
			require_cmd 'nfsd_debug.exe' || (( numerr++ ))
			require_cmd 'nfs_mount.exe' || (( numerr++ ))
			require_cmd 'ksh93.exe' || (( numerr++ ))
			require_file '/lib/msnfs41client/cygwin_idmapper.ksh' || (( numerr++ ))
			if ! is_windows_admin_account ; then
				printf $"%s: %q requires Windows Adminstator permissions.\n" "$0" "$cmd"
				(( numerr++ ))
			fi
			(( numerr > 0 )) && return 1

			nfsclient_system_rundeamon
			return $?
			;;
		'sys_mount_globaldirs')
			check_machine_arch || (( numerr++ ))
			require_cmd 'nfs_mount.exe' || (( numerr++ ))
			require_cmd 'mountall_msnfs41client' || (( numerr++ ))
			require_cmd 'tasklist.exe' || (( numerr++ ))
			if ! is_windows_admin_account ; then
				printf $"%s: %q requires Windows Adminstator permissions.\n" "$0" "$cmd"
				(( numerr++ ))
			fi
			(( numerr > 0 )) && return 1

			nfsclient_system_mount_globaldirs
			return $?
			;;
		'sys_umount_globaldirs')
			check_machine_arch || (( numerr++ ))
			require_cmd 'nfs_mount.exe' || (( numerr++ ))
			require_cmd 'PsExec.exe' || (( numerr++ ))
			if ! is_windows_admin_account ; then
				printf $"%s: %q requires Windows Adminstator permissions.\n" "$0" "$cmd"
				(( numerr++ ))
			fi
			(( numerr > 0 )) && return 1

			nfsclient_system_umount_globaldirs
			return $?
			;;
		'mount_homedir')
			check_machine_arch || (( numerr++ ))
			require_cmd 'nfs_mount.exe' || (( numerr++ ))
			require_cmd 'tasklist.exe' || (( numerr++ ))
			(( numerr > 0 )) && return 1

			nfsclient_mount_homedir
			return $?
			;;
		'umount_homedir')
			check_machine_arch || (( numerr++ ))
			require_cmd 'nfs_mount.exe' || (( numerr++ ))
			(( numerr > 0 )) && return 1

			nfsclient_umount_homedir
			return $?
			;;
		# misc
		'watch_kernel_debuglog')
			check_machine_arch || (( numerr++ ))
			case "$(uname -m)" in
				'x86_64') require_cmd 'dbgview64' || (( numerr++ )) ;;
				'i686')   require_cmd 'dbgview' || (( numerr++ )) ;;
				*)
					printf $"%s: Unknown machine type\n" "$0" 1>&2
					(( numerr++ ))
					;;
			esac
			if ! is_windows_admin_account ; then
				printf $"%s: %q requires Windows Adminstator permissions.\n" "$0" "$cmd"
				(( numerr++ ))
			fi
			(( numerr > 0 )) && return 1

			watch_kernel_debuglog
			return $?
			;;
		'sys_terminal')
			check_machine_arch || (( numerr++ ))
			require_cmd 'mintty.exe' || (( numerr++ ))
			require_cmd 'PsExec.exe' || (( numerr++ ))
			if ! is_windows_admin_account ; then
				printf $"%s: %q requires Windows Adminstator permissions.\n" "$0" "$cmd"
				(( numerr++ ))
			fi
			(( numerr > 0 )) && return 1

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
