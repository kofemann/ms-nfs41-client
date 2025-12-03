#!/bin/bash

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
# msnfs41client.bash - simple Cygwin frontent for the msnfs41client
# NFSv4.2/NFSv4.1 filesystem driver development
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

function is_windows_64bit
{
	if [[ -d '/cygdrive/c/Windows/SysWOW64/' ]] ; then
		return 0
	else
		return 1
	fi
}

function check_machine_arch
{
	typeset winpwd
	typeset uname_m

	winpwd="$(cygpath -w "${sbinpath}")"
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

function is_service_stopped
{
	typeset service_name="$1"
	typeset -i res
	typeset stdout

	stdout="$( sc query "$service_name" )" ; (( res=$? ))

	if (( res != 0 )) ; then
		printf "%s: sc failed, msg=%q\n" "$0" "$stdout" 1>&2
		return 1
	fi

	if [[ "$stdout" == *STOPPED* ]] ; then
		return 0
	fi

	return 1
}

function is_service_installed
{
	typeset service_name="$1"
	typeset -i res

	sc getdisplayname "$service_name" >'/dev/null' 2>&1 ; (( res=$? ))

	if (( res == 0 )) ; then
		return 0
	fi

	return 1
}

function nfsclient_install
{
	set -o nounset
	set -o xtrace
	set -o errexit

	typeset cmd="$1"

	typeset use_secureboot=false

	if is_service_installed 'ms-nfs41-client-service' ; then
		if ! is_service_stopped 'ms-nfs41-client-service' ; then
			set -o xtrace # make message below more readable
			printf 'ms-nfs41-client-service is still running.\n'
			printf 'Please disable the service via $ /sbin/msnfs41client disableautostartservices #,\n'
			printf 'reboot and then install the new version of ms-nfs41-client via $ /sbin/msnfs41client install #\n'
			return 1
		fi
	fi

	# switch to the location where this script is installed,
	# because on Cygwin the script will be installed
	# in /cygdrive/c/cygwin/lib/msnfs41client/ (32bit) or
	# in /cygdrive/c/cygwin64/lib/msnfs41client/ (64bit).
	cd -P "${sbinpath}"

	# make sure all binaries are executable, Windows cmd does
	# not care, but Cygwin&bash do.
	# If *.ddl are not executable nfs*.exe fail with 0xc0000022
	typeset uname_m="$(uname -m)"
	typeset uname_s="$(uname -s)"
	typeset kernel_platform
	case "${uname_m}" in
		'x86_64')
			if [[ "${uname_s}" == *-ARM64 ]] ; then
				kernel_platform='arm64'
			else
				kernel_platform='x64'
			fi
			;;
		'i686')
			kernel_platform='i686'
			;;
		*)
			printf $"%s: Unsupported platform %q\n" "$0" "${uname_m}"
			return 1
			;;
	esac

	platform_dir="$PWD/${kernel_platform}"

	#
	# We have to use hardlinks here, because cygwin defaults to use <JUNCTION>s,
	# which neither cmd.exe nor powershell can follow. <SYMLINK>s are not an option,
	# because it woulld required the "SeCreateSymbolicLinkPrivilege", which by default
	# not even the Adminstrator has
	#

	ln -f "${platform_dir}"/nfs41_driver.*		.
	ln -f "${platform_dir}"/nfsd.*			.
	ln -f "${platform_dir}"/nfs_install.*		.
	ln -f "${platform_dir}"/nfs_mount.*		.
	ln -f "${platform_dir}"/libtirpc.*		.
	ln -f "${platform_dir}"/nfs41_np.*		.
	ln -f "${platform_dir}"/nfs41rdr.inf		.
	ln -f "${platform_dir}/VCRUNTIME140D.dll"	.
	ln -f "${platform_dir}/ucrtbased.dll"		.

	# add hardlinks in /sbin
	ln -f "nfsd".*				"../../sbin/."
	ln -f "nfs_install".*			"../../sbin/."
	ln -f "nfs_mount".*			"../../sbin/."
	ln -f "libtirpc".*			"../../sbin/."
	ln -f "VCRUNTIME140D.dll"		"../../sbin/."
	ln -f "ucrtbased.dll"			"../../sbin/."
	ln -f "../../sbin/nfs_mount.exe"	"../../sbin/nfs_umount.exe"
	if [[ "${kernel_platform}" != 'i686' ]] ; then
		ln -f 'i686/nfs_mount.release.i686.exe' "../../sbin/nfs_mount.i686.exe"
	fi

	# copy ksh93&co
	case "${kernel_platform}" in
		'x64')
			ln -f "${platform_dir}/ksh93.x86_64.exe" "../../bin/ksh93.exe"
			ln -f "${platform_dir}/shcomp.x86_64.exe" "../../bin/shcomp.exe"
			;;
		'arm64')
			if [[ -f "${platform_dir}/ksh93.arm64.exe" ]] ; then
				ln -f "${platform_dir}/ksh93.arm64.exe" "../../bin/ksh93.exe"
				ln -f "${platform_dir}/shcomp.arm64.exe" "../../bin/shcomp.exe"
			else
				ln -f "${platform_dir}/../x64/ksh93.x86_64.exe" "../../bin/ksh93.exe"
				ln -f "${platform_dir}/../x64/shcomp.x86_64.exe" "../../bin/shcomp.exe"
			fi
			;;
		'i686')
			ln -f "${platform_dir}/ksh93.i686.exe" "../../bin/ksh93.exe"
			ln -f "${platform_dir}/shcomp.i686.exe" "../../bin/shcomp.exe"
			;;
	esac

	typeset -a platformspecificexe=(
		'bin/winfsinfo'
		'bin/winclonefile'
		'bin/winoffloadcopyfile'
		'bin/winsg'
		'bin/nfs_ea'
		'sbin/catdbgprint'
		'sbin/winrunassystem'
		'sbin/nfs_globalmount'
		'usr/share/msnfs41client/tests/misc/qsortonmmapedfile1'
		'usr/share/msnfs41client/tests/misc/lockincfile1'
	)

	if [[ "${kernel_platform}" != 'i686' ]] ; then
		# lssparse needs Cygwin >= 3.5 (|lseek(..., SEEK_HOLE, ...)| support), which is not available
		# for Windows 32bit
		platformspecificexe+=( 'bin/lssparse' )
	fi

	for i in "${platformspecificexe[@]}"; do
		case "${kernel_platform}" in
			'x64')
				ln -f "../../${i}.x86_64.exe" "../../${i}.exe"
				;;
			'arm64')
				if [[ -f "../../${i}.arm64.exe" ]] ; then
					ln -f "../../${i}.arm64.exe" "../../${i}.exe"
				else
					ln -f "../../${i}.x86_64.exe" "../../${i}.exe"
				fi
				;;
			'i686')
				ln -f "../../${i}.i686.exe" "../../${i}.exe"
				;;
		esac
	done

	chmod a+x *.dll
	chmod a+x ../../sbin/nfs*.exe ../../sbin/libtirpc*.dll

	# (re-)install driver and network provider DLL(s) (nfs41_np.dll)
	nfsclient_adddriver

	mkdir -p /cygdrive/c/etc
	cp etc_netconfig /cygdrive/c/etc/netconfig
	cp ms-nfs41-idmap.conf /cygdrive/c/etc/.
	# help non-Windows admins find /etc/hosts by providing a symlink
	ln -sf /cygdrive/c/Windows/System32/drivers/etc/hosts /cygdrive/c/etc/hosts

	# enable symlink lookup
	# and then print the status
	fsutil behavior set SymlinkEvaluation L2L:1 R2R:1 L2R:1 R2L:1
	fsutil behavior query SymlinkEvaluation

	# enable Win32 long paths
	# (see https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation)
	regtool -i set '/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/FileSystem/LongPathsEnabled' 1
	od -t x4 <'/proc/registry/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/FileSystem/LongPathsEnabled'

	# use the Win10 "SegmentHeap" (see https://www.blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals.pdf)
	regtool add '/HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Image File Execution Options/nfsd.exe'
	regtool -i set '/HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Image File Execution Options/nfsd.exe/FrontEndHeapDebugOptions' 0x08
	regtool add '/HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Image File Execution Options/nfs_mount.exe'
	regtool -i set '/HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Image File Execution Options/nfs_mount.exe/FrontEndHeapDebugOptions' 0x08
	regtool add '/HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Image File Execution Options/nfs_umount.exe'
	regtool -i set '/HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Image File Execution Options/nfs_umount.exe/FrontEndHeapDebugOptions' 0x08

	if ! $use_secureboot ; then
		# make sure we can load the kernel driver
		# (does not work with SecureBoot)
		bcdedit /set testsigning on

		# enable local kernel debugging
		bcdedit /debug on
		bcdedit /dbgsettings local
	fi

	# set domain name
	typeset win_domainname=''
	if [[ -f '/proc/registry/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/Tcpip/Parameters/Domain' ]] ; then
		win_domainname="$( strings '/proc/registry/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/Tcpip/Parameters/Domain' )"
	fi
	if [[ "${win_domainname}" == '' ]] ; then
		regtool -s set '/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/Tcpip/Parameters/Domain' 'GLOBAL.LOC'
	fi

	# disable DFS
	#
	# Notes:
	# - no longer needed because we have the UNC hostname@port layout
	# - Use $ sc config Dfsc start=system to undo this
	#sc query Dfsc
	#sc stop Dfsc || true
	#sc config Dfsc start=disabled

	sc query nfs41_driver
	domainname

	#openfiles /local ON
	openfiles /local OFF

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
			printf '# at system boot time to mount global shares\n'
			printf '#\n\n'
			printf '# nfs://[fe80::21b:1bff:fec3:7713]//bigdisk\tN:\tnfs\tsec=sys,rw\t0\t0\n\n'
			printf '# EOF.\n'
		} >'/etc/fstab.msnfs41client'
	fi

	if [[ "$cmd" != *devinstall* ]] ; then
		nfsclient_enable_autostartservices
	fi

	# query new 'ms-nfs41-client-service'
	sc query 'ms-nfs41-client-service'
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

function nfsclient_enable_autostartservices
{
	sc config 'ms-nfs41-client-service' start=auto
	sc config 'ms-nfs41-client-globalmountall-service' start=auto
}

function nfsclient_disable_autostartservices
{
	sc config 'ms-nfs41-client-service' start=disabled
	sc config 'ms-nfs41-client-globalmountall-service' start=disabled
}

function nfsclient_adddriver
{
	typeset -i res

	set -o nounset
	set -o xtrace
	set -o errexit

	# switch to the location where this script is installed,
	# because on Cygwin the script will be installed
	# in /cygdrive/c/cygwin/lib/msnfs41client/ (32bit) or
	# in /cygdrive/c/cygwin64/lib/msnfs41client/ (64bit).
	cd -P "${sbinpath}"

	# devel: set default in case "nfs_install" ruined it:
	#regtool -s set '/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/NetworkProvider/Order/ProviderOrder' 'RDPNP,LanmanWorkstation,webclient'

	printf 'before nfs_install: ProviderOrder="%s"\n' "$( strings -a '/proc/registry/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/NetworkProvider/Order/ProviderOrder')"
	nfs_install -D
	printf 'after nfs_install:  ProviderOrder="%s"\n' "$( strings -a '/proc/registry/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/NetworkProvider/Order/ProviderOrder')"

	if ${use_nfs41rdrinf} ; then
		rundll32 setupapi.dll,InstallHinfSection DefaultInstall 132 ./nfs41rdr.inf
	else
		#
		# Install kernel driver and network provider DLL "manually"
		# (this is the same functionality which the nfs41rdr.inf should do)
		#
		rm -f '/cygdrive/c/Windows/System32/drivers/nfs41_driver.sys'
		cp 'nfs41_driver.sys' '/cygdrive/c/Windows/System32/drivers/nfs41_driver.sys'
		rm -f '/cygdrive/c/Windows/System32/nfs41_np.dll'
		cp 'nfs41_np.dll' '/cygdrive/c/Windows/System32/nfs41_np.dll'

		#
		# create nfs41_driver service if it does not exists
		# (ERROR_SERVICE_DOES_NOT_EXIST==1060, 1060-1024==36)
		#
		set +o errexit
		sc query nfs41_driver >'/dev/null' 2>&1
		(( res=$? ))
		set -o errexit

		if (( res == 36 )) ; then
			sc create nfs41_driver binPath='C:\Windows\System32\drivers\nfs41_driver.sys' type=filesys group=network start=system tag=8
		fi

		regtool add '/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/nfs41_driver'
		regtool add '/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/nfs41_driver/NetworkProvider'
		regtool -s set '/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/nfs41_driver/NetworkProvider/DeviceName' '\Device\nfs41_driver'
		regtool -s set '/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/nfs41_driver/NetworkProvider/Name' 'NFS41 Network'
		regtool -s set '/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/nfs41_driver/NetworkProvider/ProviderPath' 'System32\nfs41_np.dll'
	fi

	#
	# Hack: Manually Add 32bit provider DLL to a 64bit system, so
	# 32bit applications can enumerate the ms-nfs41-client shares
	# (FIXME: technically nfs41rdr.inf should do this)
	#
	if is_windows_64bit ; then
		# copy from the 32bit install dir
		rm -f '/cygdrive/c/Windows/SysWOW64/nfs41_np.dll'
		cp './i686/nfs41_np.release.dll' '/cygdrive/c/Windows/SysWOW64/nfs41_np.dll'
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
	cd -P "${sbinpath}"

	nfs_install.exe 0

	if ${use_nfs41rdrinf} ; then
		rundll32.exe setupapi.dll,InstallHinfSection DefaultUninstall 132 ./nfs41rdr.inf

		# nfs41rdr.inf should do this, but we do this here for testing
		if [[ -f '/cygdrive/c/Windows/System32/drivers/nfs41_driver.sys' ]] ; then
			printf '# %q leftover from INF uninstall, removing...\n' \
				'/cygdrive/c/Windows/System32/drivers/nfs41_driver.sys'
			rm -f '/cygdrive/c/Windows/System32/drivers/nfs41_driver.sys' || true
		fi
		if [[ -f '/cygdrive/c/Windows/System32/nfs41_np.dll' ]] ; then
			printf '# %q leftover from INF uninstall, removing...\n' \
				'/cygdrive/c/Windows/System32/nfs41_np.dll'
			rm -f '/cygdrive/c/Windows/System32/nfs41_np.dll' || true
		fi
	else
		#
		# Remove kernel driver and network provider DLL "manually"
		# (this is the same functionality which the nfs41rdr.inf should do)
		#

		#sc stop nfs41_driver
		#sc delete nfs41_driver

		# regtool fails with an error if we try to delete the nfs41_driver dir
		reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nfs41_driver" /f || true

		rm -f '/cygdrive/c/Windows/System32/drivers/nfs41_driver.sys' || true
		rm -f '/cygdrive/c/Windows/System32/nfs41_np.dll' || true
	fi

	#
	# Hack: Manually remove 32bit provider DLL on a 64bit system,
	# (see comment in "nfsclient_adddriver")
	#
	if is_windows_64bit ; then
		rm -f '/cygdrive/c/Windows/SysWOW64/nfs41_np.dll' || true
	fi

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

	#
	# start kernel driver if it is not running yet
	# (can happen directly after installation if no reboot was made)
	#
	sc start nfs41_driver || true

	# switch to UTF-8 codepage so debug output with non-ASCII characters
	# gets printed correctly on a terminal
	chcp.com 65001

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
		#
		# Useful cdb cmds:
		# - heap tests (eats lots of memory):
		# '-c' '!gflag +full;g' for heap tests
		# - log all |malloc()|/|calloc()| calls:
		# '-c' 'bp ucrtbase!malloc "kp; g" ; bp ucrtbased!_malloc_dbg "kp; g" ; bp ucrtbase!calloc "kp; g" ; bp ucrtbased!_calloc_dbg "kp; g" ; g'
		#
		nfsd_args=(
			'cdb'
			'-c' '!gflag +soe;sxe -c "kp;gn" *;.lines -e;g'
			"$(cygpath -w "${sbinpath}/${nfsd_args[0]}")"
			"${nfsd_args[@]:1}"
		)
		"${nfsd_args[@]}"
	elif false ; then
		#
		# test nfsd.exe with Dr. Memory (version 2.6.2028 -- build 0)
		#
		export _NT_ALT_SYMBOL_PATH="$(cygpath -w "${sbinpath}")"
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
				'-check_uninit_non_moves'
				'-check_uninit_all'
				'-strict_bitops'
				'-gen_suppress_syms'
				'-preload_symbols'
				# no symbol cache, user "SYSTEM" cannot write data to cache
				'-no_use_symcache'
				# disable leak checking for performance
				'-no_check_leaks'
				'--'
				"$(cygpath -w "$(which "${nfsd_args[0]}")")"
				"${nfsd_args[@]:1}"
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
			"/launch:$(cygpath -w "${sbinpath}/nfsd.exe")" \
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

	#
	# start kernel driver if it is not running yet
	# (can happen directly after installation if no reboot was made)
	#
	sc start nfs41_driver || true

	# switch to UTF-8 codepage so debug output with non-ASCII characters
	# gets printed correctly on a terminal
	chcp.com 65001

	# make sure nfsd running as user "SYSTEM" can write
	# its log files to CWD
	# We explicitly use the SID ("S-1-5-18") for user "SYSTEM",
	# because the username can be localised, e.g.
	# $'Syst\xc3\xa8me' for French Windows
	icacls "$(cygpath -w "$PWD")" /grant '*S-1-5-18:(F)'

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
		export _NT_ALT_SYMBOL_PATH="$(cygpath -w "${sbinpath}");srv*https://msdl.microsoft.com/download/symbols"
		# - heap tests (eats lots of memory):
		# '-c' '!gflag +full;g' for heap tests
		# - log all |malloc()|/|calloc()| calls:
		# '-c' 'bp ucrtbase!malloc "kp; g" ; bp ucrtbased!_malloc_dbg "kp; g" ; bp ucrtbase!calloc "kp; g" ; bp ucrtbased!_calloc_dbg "kp; g" ; g'
		#
		nfsd_args=(
			'cdb'
			'-c' '!gflag +soe;sxe -c "kp;gn" *;.lines -e;g'
			"$(cygpath -w "${sbinpath}/${nfsd_args[0]}")"
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
		export _NT_ALT_SYMBOL_PATH="$(cygpath -w "${sbinpath}")"
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
				'-check_uninit_non_moves'
				'-check_uninit_all'
				'-strict_bitops'
				'-gen_suppress_syms'
				'-preload_symbols'
				# no symbol cache, user "SYSTEM" cannot write data to cache
				'-no_use_symcache'
				# disable leak checking for performance
				'-no_check_leaks'
				'--'
				"$(cygpath -w "$(which "${nfsd_args[0]}")")"
				"${nfsd_args[@]:1}"
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
			"/launch:$(cygpath -w "${sbinpath}/nfsd.exe")" \
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

function attach_debugger_to_daemon
{
	set -o nounset
	set -o xtrace
	set -o errexit

	typeset nfsd_winpid
	typeset dummy

	export NT_ALT_SYMBOL_PATH="$(cygpath -w "${sbinpath}");srv*https://msdl.microsoft.com/download/symbols"

	# Get Windows pid of nfsd.exe
	read dummy nfsd_winpid < <(tasklist /FI "IMAGENAME eq nfsd.exe" /FO list | fgrep 'PID:')

	cdb '-c' '!gflag +soe;sxe -c "kp;gn" *;.lines -e;g' -p ${nfsd_winpid}

	return $?
}

function watch_kernel_debuglog
{
	printf "# logging start...\n" 1>&2

	catdbgprint

	printf '# logging done\n' 1>&2
	return 0
}

function watch_nfs_traffic
{
	typeset -i nfsv4port=2049
	typeset s
	typeset -a eth_interface_list=()

	printf '# %s: Reading ethernet interface list\n' "$0"
	while read s ; do
		eth_interface_list+=( "${s/$'\r'/}" )
	done < <(powershell -Command 'Get-NetAdapter -Physical | Where-Object { $_.Status -eq "Up"} | ForEach-Object {$_.Name}')

	printf '# Found interface %q\n' "${eth_interface_list[@]}"

	# args to watch NFSv4.x RFC traffic
	typeset -a tshark_args=(
		'-f' "port $nfsv4port"
		'-d' "tcp.port==${nfsv4port},rpc"
	)

	# add ethernet interface names
	for s in "${eth_interface_list[@]}" ; do
		tshark_args+=( '-i' "$s" )
	done

	'/cygdrive/c/Program Files/Wireshark/tshark' "${tshark_args[@]}"

	return 0
}

function nfsclient_system_mount_globaldirs
{
	set -o xtrace
	set -o nounset
	set -o errexit

	if ! nfsclient_waitfor_clientdaemon ; then
		printf $"%s: nfsd*.exe not running.\n" "$0" 1>&2
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
		printf $"%s: nfsd*.exe not running.\n" "$0" 1>&2
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
		printf $"%s: File %q not found in %q\n" "$0" "$testfile" "$PWD" 1>&2
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

typeset sbinpath

function main
{
	typeset cmd="$1"
	typeset -i numerr=0

	#
	# path where this script is installed
	# we save this path so we can have a different installation root
	# (ReactOS netboot etc.) than just /cygdrive/c/
	#
	if [[ -v KSH_VERSION ]] ; then
		sbinpath="$(dirname -- "$(realpath "${.sh.file}")")"
	else
		sbinpath="$(dirname -- "$(realpath "${BASH_SOURCE[0]}")")"
	fi

	# "$PATH:/usr/bin:/bin" is used for PsExec where $PATH might be empty
	PATH="$PWD:$PATH:${sbinpath}/../../lib/msnfs41client:${sbinpath}/../../usr/bin:${sbinpath}/../../bin:${sbinpath}/../../sbin:${sbinpath}/../../usr/sbin"
	# add defauft system path for POSIX utilities
	PATH+=':/sbin:/usr/sbin:/bin:/usr/bin'

	# add Windows tools path (tasklist, taskkill etc.)
	PATH+=':/cygdrive/c/Windows/system32/'

	if is_windows_64bit ; then
		# path to WinDBG cdb (fixme: 64bit x86-specific)
		PATH+=':/cygdrive/c/Program Files (x86)/Windows Kits/10/Debuggers/x64/'

		# PATH to DrMemory
		PATH+=':/cygdrive/c/Program Files (x86)/Dr. Memory/bin/'
	else
		# path to WinDBG cdb (fixme: 64bit x86-specific)
		PATH+=':/cygdrive/c/Program Files/Windows Kits/10/Debuggers/x86/'

		# PATH to DrMemory
		PATH+=':/cygdrive/c/Program Files/Dr. Memory/bin'
	fi

	# PATH to VSDiagnostics.exe and AgentConfigs
	vsdiagnostics_path='/cygdrive/c/Program Files (x86)/Microsoft Visual Studio/2019/Community/Team Tools/DiagnosticsHub/Collector/'
	PATH+=":${vsdiagnostics_path}"

	# my own path to pstools
	PATH+=':/home/roland_mainz/work/win_pstools/'

	# my own path to DebugView
	PATH+=':/cygdrive/c/Users/roland_mainz/download/DebugView'

	case "$cmd" in
		'install' | 'devinstall')
			check_machine_arch || (( numerr++ ))
			require_cmd 'regtool.exe' || (( numerr++ ))
			require_cmd 'cygrunsrv.exe' || (( numerr++ ))
			require_cmd 'rundll32.exe' || (( numerr++ ))
			require_cmd 'bcdedit.exe' || (( numerr++ ))
			require_cmd 'fsutil.exe' || (( numerr++ ))
			require_cmd 'sc.exe' || (( numerr++ ))
			if ! is_windows_admin_account ; then
				printf $"%s: %q requires Windows Adminstator permissions.\n" "$0" "$cmd"
				(( numerr++ ))
			fi
			(( numerr > 0 )) && return 1

			nfsclient_install "$cmd"
			return $?
			;;
		'enableautostartservices')
			check_machine_arch || (( numerr++ ))
			require_cmd 'sc.exe' || (( numerr++ ))
			if ! is_windows_admin_account ; then
				printf $"%s: %q requires Windows Adminstator permissions.\n" "$0" "$cmd"
				(( numerr++ ))
			fi
			(( numerr > 0 )) && return 1

			nfsclient_enable_autostartservices
			return $?
			;;
		'disableautostartservices')
			check_machine_arch || (( numerr++ ))
			require_cmd 'sc.exe' || (( numerr++ ))
			if ! is_windows_admin_account ; then
				printf $"%s: %q requires Windows Adminstator permissions.\n" "$0" "$cmd"
				(( numerr++ ))
			fi
			(( numerr > 0 )) && return 1

			nfsclient_disable_autostartservices
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
		'attach_debugger_to_daemon')
			check_machine_arch || (( numerr++ ))
			require_cmd 'tasklist.exe' || (( numerr++ ))
			require_cmd 'cdb.exe' || (( numerr++ ))
			if ! is_windows_admin_account ; then
				printf $"%s: %q requires Windows Adminstator permissions.\n" "$0" "$cmd"
				(( numerr++ ))
			fi
			(( numerr > 0 )) && return 1

			attach_debugger_to_daemon
			return $?
			;;
		'watch_kernel_debuglog')
			check_machine_arch || (( numerr++ ))
			require_cmd 'catdbgprint' || (( numerr++ ))
			if ! is_windows_admin_account ; then
				printf $"%s: %q requires Windows Adminstator permissions.\n" "$0" "$cmd"
				(( numerr++ ))
			fi
			(( numerr > 0 )) && return 1

			watch_kernel_debuglog
			return $?
			;;
		'watch_nfs_traffic')
			check_machine_arch || (( numerr++ ))
			require_cmd 'powershell' || (( numerr++ ))
			require_cmd '/cygdrive/c/Program Files/Wireshark/tshark' || (( numerr++ ))

			(( numerr > 0 )) && return 1

			watch_nfs_traffic
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

# Our current nfs41rdr.inf file does not work on Windows 11/ARM64,
# therefore use the "manual driver install" codepath for now
# until we fixed the nfs41rdr.inf
typeset -r use_nfs41rdrinf=false

if [[ -v KSH_VERSION ]] ; then
	#
	# use ksh93 builtins
	# (and make it fatal if they are missing)
	#
	set -o errexit
	builtin cat
	builtin chmod
	builtin chown
	builtin cp
	builtin dirname
	builtin id
	builtin ln
	builtin md5sum
	builtin mkdir
	builtin mv
	builtin rm
	builtin rmdir
	builtin sync
	builtin tail
	builtin uname
	PATH="/usr/ast/bin:/opt/ast/bin:$PATH"
	set +o errexit
fi

main "$@"
exit $?

# EOF.
