#!/bin/ksh93

#
# MIT License
#
# Copyright (c) 2023-2024 Roland Mainz <roland.mainz@nrubsig.org>
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
# mount_sshnfs - mount NFSv4 filesystem through ssh tunnel
#

#
# Example usage:
#
# 1. UNIX/Linux: Mount&&unmount /export/home/rmainz on NFS server "/export/home/rmainz":
# $ mkdir -p /foobarmnt
# $ ksh mount_sshnfs.ksh mount ssh+nfs://rmainz@derfwpc5131//export/home/rmainz /foobarmnt
# $ mount_sshnfs.ksh umount /foobarmnt
#
#
# 2. UNIX/Linux: Mount&&unmount /export/home/rmainz on NFS server "/export/home/rmainz" via SSH jumphost rmainz@10.49.20.131:
# $ mkdir -p /foobarmnt
# $ ksh mount_sshnfs.ksh mount -o ro,mount_sshnfs_jumphost=rmainz@10.49.20.131 ssh+nfs://rmainz@derfwpc5131//export/home/rmainz /foobarmnt
# $ mount_sshnfs.ksh umount /foobarmnt
#

#
# For more examples see help and subcommand help:
# $ mount_sshnfs --man
# $ mount_sshnfs mount --man
# $ mount_sshnfs umount --man
#

#
# Written by Roland Mainz <roland.mainz@nrubsig.org>
#

function usage
{
	(( OPTIND=0 ))
	getopts -a "${1}" "${2}" OPT '-?'
	return 2
}


#
# simple netstat -n parser
#
function netstat_list_connections
{
	set -o nounset
	nameref data=$1

	compound out=( typeset stdout stderr ; integer res )

	out.stderr="${ { out.stdout="${ LC_ALL='POSIX' PATH='/usr/bin:/bin' netstat -a -n ; (( out.res=$? )) ; }" ; } 2>&1 ; }"
	if (( out.res != 0 )) ; then
		print -u2 -f $"%s: netstat returned %d exit code.\n" \
			"$0" out.res
		return 1
	fi
	if [[ "${out.stderr}" != '' ]] ; then
		#
		# Handle known Linux netstat warnings
		#
		if [[ "${out.stderr}" != $'warning, got bogus unix line.' ]] ; then
			print -u2 -f $"%s: netstat returned unknown error message %q.\n" \
				"$0" "${out.stderr}"
			return 1
		fi
	fi

	typeset -a data.connections
	typeset l
	typeset leftover
	integer dci=0 # data.connections array index

	while read l ; do
		leftover="${l/~(Elrx)
		(?: # non-capturing group
			#
			# regex group for tcp,udp
			#
			(tcp|tcp6|udp|udp6|raw|raw6|sctp|sctp6)	# Proto
			[[:space:]]+
			([[:digit:]]+)			# Recv-Q
			[[:space:]]+
			([[:digit:]]+)			# Send-Q
			[[:space:]]+
			([^[:space:]]+)			# Local Address
			[[:space:]]+
			([^[:space:]]+)			# Foreign Address
			(?:
				|
				[[:space:]]+
				([^[:space:]]*?) 	# State (Optional)
			)
		|
			#
			# regex for unix
			#
			(unix)				# Proto
			[[:space:]]+
			([[:digit:]]+)			# RefCnt
			[[:space:]]+
			(\[.+?\])			# Flags
			[[:space:]]+
			([^[:space:]]+) 		# Type
			[[:space:]]+
			([^[:space:]]*?)		# State (optional)
			[[:space:]]+
			([[:digit:]]+)			# I-Node
			(?:
				|
				[[:space:]]+
				([^[:space:]]+)		# Path (optional)
			)
		)
			/X}"

		# If the regex above did not match then .sh.match
		# remains untouched, so we might see data from the
		# previous round.
		# So we check the "leftover" var whether it just
		# contains the dummy value of "X" to indicate a
		# successful regex match
		if [[ "$leftover" == 'X' ]] ; then
			#print -v .sh.match

			if [[ "${.sh.match[1]-}" != '' ]] ; then
				nameref dcn=data.connections[$dci]

				typeset dcn.proto="${.sh.match[1]}"
				typeset dcn.recv_q="${.sh.match[2]}"
				typeset dcn.send_q="${.sh.match[3]}"
				typeset dcn.local_address="${.sh.match[4]}"
				typeset dcn.foreign_address="${.sh.match[5]}"
				typeset dcn.state="${.sh.match[6]}"
				((dci++))
			elif [[ "${.sh.match[7]-}" != '' ]] ; then
				nameref dcn=data.connections[$dci]

				typeset dcn.proto="${.sh.match[7]}"
				typeset dcn.refcnt="${.sh.match[8]}"
				typeset dcn.flags="${.sh.match[9]}"
				typeset dcn.type="${.sh.match[10]}"
				[[ "${.sh.match[11]}" != '' ]] && typeset dcn.state="${.sh.match[11]}"
				typeset dcn.inode="${.sh.match[12]}"
				[[ "${.sh.match[13]}" != '' ]] && typeset dcn.path="${.sh.match[13]}"
				((dci++))
			fi
		else
			true
			#printf $"leftover=%q\n" "${leftover}"
		fi
	done <<<"${out.stdout}"

	return 0
}

function netstat_list_active_local_tcp_connections
{
	set -o nounset
	nameref ar=$1
	compound c
	integer port
	integer i

	netstat_list_connections c || return 1
	#print -v c

	[[ -v ar ]] || integer -a ar

	for i in "${!c.connections[@]}" ; do
		nameref n=c.connections[$i]

		# look for only for TCP connections which match
		# 127.0.*.* or IPv6 ::1 for localhost
		# 0.0.0.0 or IPv6 :: for all addresses (e.g. servers)
		if [[ "${n.proto}" == ~(El)tcp && \
			"${n.local_address}" == ~(Elr)((127\.0\..+|::1)|(::|0\.0\.0\.0|)):[[:digit:]]+ ]] ; then

			port="${n.local_address##*:}"
			#printf $"port = %d\n" port

			(( ar[port]=1 ))
		fi
	done

	return 0
}

function netstat_find_next_free_local_tcp_port
{
	set -o nounset
	compound c=( integer -a ar )
	nameref ret_free_port=$1
	integer start_port
	integer end_port
	integer i

	netstat_list_active_local_tcp_connections c.ar || return 1

	#print -v c

	(( start_port=$2 ))
	if (( $# > 2 )) ; then
		(( end_port=$3 ))
	else
		(( end_port=65535 ))
	fi

	for ((i=start_port ; i < end_port ; i++ )) ; do
		if [[ ! -v c.ar[i] ]] ; then
			(( ret_free_port=i ))
			return 0
		fi
	done

	return 1
}


function urldecodestr
{
	nameref out=$1
	typeset s="$2"

	#
	# build format string for printf(1) ...
	#

	# quote backslashes
	s="${s//$'\\'/$'\\\\'}"
	# urldecode '+' to ' '
	s="${s//+/ }"
	# urldecode %<hexdigit><hexdigit>
	s="${s//~(E)(?:%([[:xdigit:]][[:xdigit:]]))/\\x\1}"
	# quote any remaining "%" to make it safe for printf(1)
	s="${s//%/%%}"

	#
	# ... and then let printf(1) do the formatting
	#
	out="${ printf "$s" ; }"
	return 0
}


#
# parse_rfc1738_url - parse RFC 1838 URLs
#
# Output variables are named after RFC 1838 Section 5 ("BNF for
# specific URL schemes")
#
function parse_rfc1738_url
{
	set -o nounset

	typeset url="$2"
	typeset leftover
	nameref data="$1" # output compound variable
	typeset url_param_str

	# ~(E) is POSIX extended regular expression matching (instead
	# of shell pattern), "x" means "multiline", "l" means "left
	# anchor", "r" means "right anchor"
	leftover="${url/~(Elrx)
		(.+?)				# scheme
		:\/\/				# '://'
		(				# login
			(?:
				(.+?)		# user (optional)
				(?::(.+))?	# password (optional)
				@
			)?
			(			# hostport
				(.+?)		# host
				(?::([[:digit:]]+))? # port (optional)
			)
		)
		(?:\/(.*?))?			# path (optional)
		(?:\?(.*?))?			# URL parameters (optional)
		/X}"

	# All parsed data should be captured via eregex in .sh.match - if
	# there is anything left (except the 'X') then the input string did
	# not properly match the eregex
	[[ "$leftover" == 'X' ]] ||
		{ print -u2 -f $"%s: Parser error, leftover=%q\n" \
			"$0" "$leftover" ; return 1 ; }

	data.url="${.sh.match[0]}"
	data.scheme="${.sh.match[1]}"
	data.login="${.sh.match[2]}"
	# FIXME: This should use [[ ! -v .sh.match[3] ]], but ksh93u has bugs
	[[ "${.sh.match[3]-}" != '' ]] && data.user="${.sh.match[3]}"
	[[ "${.sh.match[4]-}" != '' ]] && data.password="${.sh.match[4]}"
	data.hostport="${.sh.match[5]}"
	data.host="${.sh.match[6]}"
	[[ "${.sh.match[7]-}" != '' ]] && integer data.port="${.sh.match[7]}"
	[[ "${.sh.match[8]-}" != '' ]] && data.uripath="${.sh.match[8]}"

	if [[ "${.sh.match[9]-}" != '' ]] ; then
		compound -a data.parameters

		url_param_str="${.sh.match[9]-}"

		while [[ "$url_param_str" != '' ]] ; do
			leftover="${url_param_str/~(Elrx)(?:(.+?)(?:=(.+?))?)(?:&(.*))?/X}"

			# save matches because urldecodestr uses .sh.match, too
			typeset dp_name="${.sh.match[1]-}"
			typeset dp_value="${.sh.match[2]-}"
			typeset dp_next="${.sh.match[3]-}"

			urldecodestr dp_name "${dp_name}"
			urldecodestr dp_value "${dp_value}"

			data.parameters+=(
				name="${dp_name}"
				value="${dp_value}"
				)

			# next parameter
			url_param_str="${dp_next}"
		done
	fi

	if [[ -v data.uripath ]] ; then
		urldecodestr data.path "${data.uripath}"
	fi

	return 0
}


function parse_sshnfs_url
{
	typeset url="$2"
	nameref data="$1"

	parse_rfc1738_url data "$url" || return 1

	[[ "${data.scheme}" == ~(Elr)(ssh\+nfs|nfs) ]] || \
		{ print -u2 -f $"%s: Not a nfs:// or ssh+nfs:// url\n" "$0" ; return 1 ; }
	[[ "${data.host}" != '' ]] || { print -u2 -f $"%s: NFS hostname missing\n" "$0" ; return 1 ; }
	[[ "${data.uripath}" != '' ]] || { print -u2 -f $"%s: NFS path missing\n" "$0" ; return 1 ; }
	[[ "${data.uripath}" == /* ]] || { print -u2 -f $"%s: NFS path (%q) must be absolute\n" "$0" "${data.uripath}" ; return 1 ; }
	[[ "${data.uripath}" != //* ]] || { print -u2 -f $"%s: NFS path (%q) should not start with '//' \n" "$0" "${data.uripath}" ; return 1 ; }

	return 0
}


function mountpoint2configfilename
{
	nameref configfilename=$1
	typeset mountpoint="$2"

	#
	# FIXME:
	# - We should urlencode more than just '/'
	# - We should strip the leading '/'
	# - We should use realpath(1) for mountpoints here
	#

	# .cpv means ComPound Variable"
	configfilename="/tmp/mount_sshnfs/${mountpoint//\//%2f}.cpv"
	return 0
}


function kernel_supports_nfs42_client
{
	typeset s=''

	if [[ "$(uname -s)" == 'Linux' ]] ; then
		if [[ -r '/proc/config.gz' ]] ; then
			s="$(gunzip -c <'/proc/config.gz' | egrep -v '^[[:space:]]*#')"
		elif [[ -r "/boot/config-$(uname -r)" ]] ; then
			s="$( egrep -v '^[[:space:]]*#' "/boot/config-$(uname -r)")"
		fi

		if [[ "$s" == *CONFIG_NFS_V4_2=y* ]] ; then
			return 0
		fi

		return 1
	else
		# FIXME: Add more OS support
		true
	fi

	return 2
}


function cmd_mount
{
	set -o nounset
	nameref c=$1

	# fixme: Need better text layout for $ mount_sshnfs mount --man #
	typeset -r mount_sshnfs_cmdmount_usage=$'+
	[-?\n@(#)\$Id: mount_sshnfs mount (Roland Mainz) 2024-07-08 \$\n]
	[-author?Roland Mainz <roland.mainz@nrubsig.org>]
	[+NAME?mount_sshnfs mount - mount NFSv4 filesystem through ssh
		tunnel]
	[+DESCRIPTION?\bmount_sshnfs mount\b mounts a NFSv4 filesystem
		through a ssh tunnel.]
	[r:readonly?Mount file system readonly.]
	[w:readwrite?Mount file system read-write.]
	[o:options?Use the specified mount options.
		The opts argument is a comma-separated list.\n
		options starting with mount_sshnfs_jumphost_* will be
		consumed by mount_sshnfs, all other options will be
		passed through to mount.nfs.]:[options]{
		[+?mount_sshnfs options are:]{
			[+?-o mount_sshnfs_jumphost=user@host:port - ssh jumphost]
			[+?-o mount_sshnfs_local_forward_port=port - local TCP port
				for SSH-forwarded NFS connection to server.
				Defaults is to use netstat(1) to find a free TCP port]
			}
		}

	url mountpoint

	[+NOTES?]{
		[+?The original CITI Windows NFSv4 nfs_mount.exe does not
		support the port= option.\nUse -o mount_sshnfs_local_forward_port=2049
		as workaround. Newer versions from https://github.com/kofemann/ms-nfs41-client
		support the -o port=... option.]
		}
	[+SEE ALSO?\bksh93\b(1),\bssh\b(1),\bmount.nfs\b(8),\bnfs\b(5)]
	'
	typeset mydebug=false	# fixme: should be "bool" for ksh93v
	typeset c.url
	typeset c.mountpoint
	typeset config_filename

	typeset -a c.mount_nfs_options
	integer i
	integer saved_optind_m1	# saved OPTIND-1
	typeset s		# generic temporary string variable

	# remove subcmd name (in this case 'mount')
	unset c.args[0]

	#
	# Expand MOUNT_SSHNFS_CMDMOUNT_OPTIONS before arguments given to
	# mount_sshnfs.ksh.
	# By default we use IFS=$' \t\n' for argument splitting
	#
	c.args=( ${MOUNT_SSHNFS_CMDMOUNT_OPTIONS-} "${c.args[@]}" )

	#
	# Argument parsing
	#
	while getopts -a "${progname} mount" "${mount_sshnfs_cmdmount_usage}" OPT "${c.args[@]}" ; do
		case "${OPT}" in
			'r')
				c.mount_nfs_options+=( 'ro' )
				;;
			'w')
				c.mount_nfs_options+=( 'rw' )
				;;
			'o')
				#
				# Split options like "-o foo=bar,baz=BAM"
				# into "-o foo=bar -o baz=BAM" for easier
				# processing below
				IFS=$','
				c.mount_nfs_options=( "${c.mount_nfs_options[@]}" ${OPTARG} )
				IFS=$' \t\n'
				;;
			*)
				usage "${progname} mount" "${mount_sshnfs_cmdmount_usage}"
				return $?
				;;
		esac
	done

	(( saved_optind_m1=OPTIND-1 ))

	# remove options we just parsed from c.args
	for ((i=0 ; i < saved_optind_m1 ; i++)) ; do
		unset c.args[$i]
	done


	#
	# Get remaining arguments
	#
	c.url="${c.args[saved_optind_m1+0]-}"
	c.mountpoint="${c.args[saved_optind_m1+1]-}"


	#
	# Filter out our options, other options are passed to mount.nfs
	#
	for ((i=0 ; i < ${#c.mount_nfs_options[@]} ; i++)) ; do
		s="${c.mount_nfs_options[$i]}"

		#
		# Intercept options starting with eregex mount_sshnfs.+
		#
		if [[ "$s" == ~(Elr)mount_sshnfs.+=.+ ]] ; then
			case "$s" in
				~(Eli)mount_sshnfs_jumphost=)
					[[ ! -v c.ssh_jumphost_args ]] && typeset -a c.ssh_jumphost_args
					c.ssh_jumphost_args+=( "-J" "${c.mount_nfs_options[i]/~(Eli)mount_sshnfs_jumphost=}" )
					;;
				~(Eli)mount_sshnfs_local_forward_port=)
					# command(1) prevents that the shell interpreter
					# exits if typeset produces a syntax error
					command integer c.local_forward_port="${c.mount_nfs_options[i]/~(Eli)mount_sshnfs_local_forward_port=}" || return 1
					;;
				*)
					usage "${progname} mount" "${mount_sshnfs_cmdmount_usage}"
					return $?
					;;
			esac
			unset c.mount_nfs_options[$i]
		fi
	done


	#
	# Parse url
	#
	parse_sshnfs_url c.nfs_server "${c.url}" || return 1

	mountpoint2configfilename config_filename "${c.mountpoint}"

	if [[ -f "${config_filename}" ]] ; then
		print -u2 -f $"%s: Config file %q for mount point %q found.\n" \
			"$0" \
			"$config_filename" \
			"${c.mountpoint}"
		return 1
	fi

	#
	# Prechecks for writing the config file
	#
	mkdir -p '/tmp/mount_sshnfs/'
	if [[ ! -w '/tmp/mount_sshnfs/' ]] ; then
		print -u2 -f $"%s: mount_nfs data directory %q not writeable.\n" \
			"$0" \
			'/tmp/mount_sshnfs/'
		return 1
	fi

	${mydebug} && print -v c

	case "${c.nfs_server.scheme}" in
		'ssh+nfs')
			#
			# Find free local forwarding port
			#

			# Note: Original CITI ms-nfsv41 client
			# nfs_mount.exe
			# does not support -o port=..., so we set a default
			# here if it was not set yet
			if (( c.is_ccygwin == 1 )) && [[ ! -v c.local_forward_port ]] ; then
				integer c.local_forward_port=2049
			fi

			# port on THIS machine
			if [[ ! -v c.local_forward_port ]] ; then
				integer c.local_forward_port

				(( i=34049 ))
				if ! netstat_find_next_free_local_tcp_port c.local_forward_port $i ; then
					print -u2 -f "%s: netstat_find_next_free_local_tcp_port failed.\n" "$0"
					return 1
				fi
			fi


			c.ssh_control_socket_name="/tmp/mount_sshnfs/mount_sshnfs_ssh-control-socket_logname${LOGNAME}_ppid${PPID}_pid$$"

			#
			# Find SSH login user name for NFS server
			#
			if [[ -v c.nfs_server.user ]] ; then
				typeset c.nfsserver_ssh_login_name="${c.nfs_server.user}"
			fi
			# fixme: Implement NFSServerSSHLoginName
			if [[ ! -v c.nfsserver_ssh_login_name ]] ; then
				# default user name if neither URL nor
				# "-o NFSServerSSHLoginName=..." were given
				typeset c.nfsserver_ssh_login_name="$LOGNAME"
			fi

			#
			# Forward NFS port from server to local machine
			#
			# Notes:
			# - We use $ ssh -M ... # here as a way to terminate the port
			# forwarding process later using "-O exit" without the need
			# for a pid
			#
			print -u2 -f $"# Please enter the login data for NFS server (%s):\n" \
				"${c.nfsserver_ssh_login_name}@${c.nfs_server.host}"

			#
			# Notes:
			# - fixme: c.nfs_server.port is fixed
			# for ssh+nfs://-URLs, so for now we
			# have to hardcode TCP/2049 for now
			# - We use aes128-cbc,aes128-ctr ciphers for better
			# throughput (see https://bash-prompt.net/guides/bash-ssh-ciphers/
			# for a benchmark) and lower latency, as NFS is
			# a bit latency-sensitive
			# - We turn compression off, as it incrases latency
			#
			ssh \
				-L "${c.local_forward_port}:localhost:2049" \
				-M -S "${c.ssh_control_socket_name}" \
				-N \
				-f -o 'ExitOnForwardFailure=yes' \
				-o 'Compression=no' \
				-o 'Ciphers=aes128-cbc,aes128-ctr' \
				"${c.ssh_jumphost_args[@]}" \
				"${c.nfsserver_ssh_login_name}@${c.nfs_server.host}"
			if (( $? != 0 )) ; then
				print -u2 -f $"%s: NFS forwarding ssh failed with error code %d\n" "$0" $?
				return 1
			fi

			# debug
			${mydebug} && \
				ssh \
					-S "${c.ssh_control_socket_name}" \
					-O 'check' \
					"${c.nfsserver_ssh_login_name}@${c.nfs_server.host}"


			if (( c.is_ccygwin == 1 )) ; then
				#
				# Build argument list for nfs_mount.exe ...
				#
				typeset -a mount_args
				for s in "${c.mount_nfs_options[@]}" ; do
					mount_args+=( '-o' "$s" )
				done

				if (( c.local_forward_port != 2049 )) ; then
					#
					# The original CITI NFSv4 nfs_mount.exe does not
					# support the port= option, so only set it
					# if we do not use the default port
					#
					mount_args+=( '-o' "port=${c.local_forward_port}" )
				fi
				# fixme: can we remove -o sec=sys ?
				mount_args+=( '-o' 'sec=sys' )
				# '*' == Let nfs_mount.exe should pick drive letter itself
				mount_args+=( '*' )
				mount_args+=( "localhost:${c.nfs_server.uripath}" )

				#
				# ... and do the mount
				#
				typeset stdout dummy

				# fixme: we should set LC_ALL=C because below we depend on
				# a l10n message
				stdout="${ "${c.msnfsv41_nfsmountcmd}" "${mount_args[@]}" ; (( retval=$? )) ;}"
				cat <<<"$stdout"

				if (( retval == 0 )) ; then
					# Parse stdout for drive letter
					dummy="${stdout/~(E)Successfully mounted (.+) to drive (?:\'|)(.+):(?:\'|)/dummy}"

					# fixme: we should test whether c.windows_drive_letter is empty or not
					typeset c.windows_drive_letter="${.sh.match[2]}"

					print -u2 -f $"%s: NFS filesystem mounted to drive %q.\n" \
						"$0" "${c.windows_drive_letter}"

					# Cygwin bind mount
					mount -o bind "/cygdrive/${c.windows_drive_letter}" "${c.mountpoint}"
				fi
			else
				#
				# Build argument list for mount.nfs ...
				#
				typeset -a mount_args
				mount_args+=( '-vvv' )
				mount_args+=( '-t' 'nfs' )
				for s in "${c.mount_nfs_options[@]}" ; do
					mount_args+=( '-o' "$s" )
				done

				if kernel_supports_nfs42_client ; then
					mount_args+=( '-o' 'vers=4.2' )
				else
					#
					# some kernels (like WSL) have a
					# Linux 5.15.x kernel with NFSv4.2
					# client support turned off
					#
					mount_args+=( '-o' 'vers=4.1' )
				fi
				mount_args+=( '-o' "port=${c.local_forward_port}" )
				mount_args+=( "localhost:${c.nfs_server.uripath}" )
				mount_args+=( "${c.mountpoint}" )

				#
				# ... and do the mount
				#
				mount "${mount_args[@]}"
				(( retval=$? ))
			fi

			if (( retval != 0 )) ; then
				#
				# Quit ssh port forwarding process
				#
				ssh \
					-S "${c.ssh_control_socket_name}" \
					-O 'exit' \
					"${c.nfsserver_ssh_login_name}@${c.nfs_server.host}"
				return $retval
			fi


			#
			# Save status data
			#
			compound mnt_config=(
				typeset url="${c.url}"
				typeset mountpoint="${c.mountpoint}"
				typeset ssh_control_socket_name="${c.ssh_control_socket_name}"
				typeset nfsserver_ssh_login_name="${c.nfsserver_ssh_login_name}"
				typeset nfsserver_host="${c.nfs_server.host}"
			)

			if (( c.is_ccygwin == 1 )) ; then
				typeset mnt_config.windows_drive_letter="${c.windows_drive_letter}"
			fi

			print -v mnt_config >"$config_filename"

			return 0
			;;
		# fixme: Implement nfs://-URLs
		*)
			print -u2 -f $"%s: Unknown URL scheme %q\n" "$0" "${c.nfs_server.scheme}"
			return 2
			;;
	esac

	# notreached
}


function cmd_umount
{
	set -o nounset
	nameref c=$1
	integer retval
	integer saved_optind_m1	# saved OPTIND-1

	typeset mydebug=false # fixme: should be "bool" for ksh93v
	# fixme: Need better text layout for $ mount_sshnfs mount --man #
	typeset -r mount_sshnfs_cmdumount_usage=$'+
	[-?\n@(#)\$Id: mount_sshnfs umount (Roland Mainz) 2024-07-08 \$\n]
	[-author?Roland Mainz <roland.mainz@nrubsig.org>]
	[+NAME?mount_sshnfs umount - unmount NFSv4 filesystem mounted
		via mount_sshnfs mount]
	[+DESCRIPTION?\bmount_sshnfs umount\b unmounts a NFSv4
		filesystem previously mounted via mount_sshnfs mount.]

	mountpoint

	[+SEE ALSO?\bksh93\b(1),\bssh\b(1),\bmount.nfs\b(8),\bnfs\b(5)]
	'

	# remove subcmd name (in this case 'umount')
	unset c.args[0]

	#
	# Expand MOUNT_SSHNFS_CMDUMOUNT_OPTIONS before arguments given to
	# mount_sshnfs.ksh.
	# By default we use IFS=$' \t\n' for argument splitting
	#
	c.args=( ${MOUNT_SSHNFS_CMDUMOUNT_OPTIONS-} "${c.args[@]}" )

	#
	# Argument parsing
	#
	while getopts -a "${progname} umount" "${mount_sshnfs_cmdumount_usage}" OPT "${c.args[@]}" ; do
		case "${OPT}" in
			*)
				usage "${progname} umount" "${mount_sshnfs_cmdumount_usage}"
				return $?
				;;
		esac
	done

	(( saved_optind_m1=OPTIND-1 ))

	# remove options we just parsed from c.args
	for ((i=0 ; i < saved_optind_m1 ; i++)) ; do
		unset c.args[$i]
	done


	#
	# Get remaining arguments
	#
	c.mountpoint="${c.args[saved_optind_m1+0]-}"

	#
	# Read configuration file for this mountpoint
	#
	typeset config_filename
	mountpoint2configfilename config_filename "${c.mountpoint}"

	if [[ ! -f "${config_filename}" ]] ; then
		print -u2 -f $"%s: Config file %q for mount point %q not found.\n" \
			"$0" \
			"$config_filename" \
			"${c.mountpoint}"
		return 1
	fi

	compound mnt_config
	read -C mnt_config <"${config_filename}" || return 1

	${mydebug} && print -v mnt_config

	#
	# Do the unmount
	#
	if (( c.is_ccygwin == 1 )) ; then
		# unmount the NFS filesystem
		"${c.msnfsv41_nfsmountcmd}" -d "${mnt_config.windows_drive_letter}"
		(( retval=$? ))

		# remove the Cygwin bind mount
		(( retval == 0 )) && umount "${c.mountpoint}"
	else
		umount "${c.mountpoint}"
		(( retval=$? ))
	fi

	if (( retval != 0 )) ; then
		return $retval
	fi

	#
	# Quit ssh port forwarding process
	#
	ssh \
		-S "${mnt_config.ssh_control_socket_name}" \
		-O 'exit' \
		"${mnt_config.nfsserver_ssh_login_name}@${mnt_config.nfsserver_host}"

	rm -f "${config_filename}"
	return 0
}


function main
{
	set -o nounset

	# fixme: Need better text layout for $ mount_sshnfs --man #
	typeset -r mount_sshnfs_usage=$'+
	[-?\n@(#)\$Id: mount_sshnfs (Roland Mainz) 2024-07-08 \$\n]
	[-author?Roland Mainz <roland.mainz@nrubsig.org>]
	[+NAME?mount_sshnfs - mount/umount NFSv4 filesystem via ssh
		tunnel]
	[+DESCRIPTION?\bmount_sshnfs\b mounts/unmounts a NFSv4
		filesystem via ssh tunnel.]
	[D:debug?Enable debugging.]

	mount [options]
	umount [options]
	status [options]
	restart_forwarding [options]
	--man

	[+EXAMPLES]{
		[+?Example 1:][+?Mount&&unmount /export/home/rmainz on NFS server "/export/home/rmainz"]{
[+\n# mkdir -p /foobarmnt
# mount_sshnfs mount ssh+nfs:://rmainz@derfwpc5131//export/home/rmainz /foobarmnt
# mount_sshnfs umount /foobarmnt
]
}
		[+?Example 2:][+?Mount&&unmount /export/home/rmainz on NFS server "/export/home/rmainz" via SSH jumphost rmainz@10.49.20.131]{
[+\n# mkdir -p /foobarmnt
# mount_sshnfs mount -o ro,mount_sshnfs_jumphost=rmainz@10.49.20.131 ssh+nfs:://rmainz@derfwpc5131//export/home/rmainz /foobarmnt
# mount_sshnfs umount /foobarmnt
]
		}
	}
	[+SEE ALSO?\bksh93\b(1),\bssh\b(1),\bmount.nfs\b(8),\bnfs\b(5)]
	'

	compound c
	typeset -a c.args
	integer saved_optind_m1	# saved OPTIND-1

	if [[ "${ uname -o ;}" == 'Cygwin' ]] ; then
		integer c.is_ccygwin=1

		# Cygwin has nfs_mount.exe in /sbin
		PATH+=':/sbin:/usr/sbin:/usr/bin:/bin'

		typeset c.msnfsv41_nfsmountcmd="$(which 'nfs_mount.exe')"

		if [[ ! -x "${c.msnfsv41_nfsmountcmd}" ]] ; then
			print -u2 -f $"%s: Cannot find MS-NFSV41 nfs_mount.exe command\n" "$0"
			return 1
		fi
	else
		integer c.is_ccygwin=0
	fi

	# Cygwin does not set logname
	[[ ! -v LOGNAME ]] && export LOGNAME="$(logname)"

	#
	# Expand MOUNT_SSHNFS_OPTIONS before arguments given to
	# mount_sshnfs.ksh.
	# By default we use IFS=$' \t\n' for argument splitting
	#
	c.args=( ${MOUNT_SSHNFS_OPTIONS-} "$@" )

	#
	# Argument parsing
	#
	while getopts -a "${progname}" "${mount_sshnfs_usage}" OPT "${c.args[@]}" ; do
		case "${OPT}" in
			'D')
				# fixme: Implement debugging option
				;;
			*)
				usage "${progname}" "${mount_sshnfs_usage}"
				return $?
				;;
		esac
	done

	(( saved_optind_m1=OPTIND-1 ))

	# remove options we just parsed from c.args
	for ((i=0 ; i < saved_optind_m1 ; i++)) ; do
		unset c.args[$i]
	done

	#
	# c.args mighth be a sparse array (e.g. "([1]=aaa [2]=bbb [4]=ccc)")
	# right now after we removed processed options/arguments.
	# For easier processing below we "reflow" the array back to a
	# normal linear layout (e.g. ([0]=aaa [1]=bbb [2]=ccc)
	#
	c.args=( "${c.args[@]}" )

	#
	# Subcommand dispatcher
	#
	case "${c.args[0]-}" in
		'mount')
			cmd_mount c
			return $?
			;;
		'umount')
			cmd_umount c
			return $?
			;;
		'status' | 'restart_forwarding')
			print -u2 -f $"%s: not implemented yet\n" "$0"
			return 2
			;;
		*)
			print -u2 -f $"%s: Unknown command %q\n" \
				"$0" "${c.args[0]-}"
			usage "${progname}" "${mount_sshnfs_usage}"
			return 1
			;;
	esac

	# notreached
}


#
# main
#
builtin cat
builtin mkdir
builtin basename

typeset progname="${ basename "${0}" ; }"

main "$@"
exit $?

# EOF.
