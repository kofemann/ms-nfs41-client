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
# sshnfs - remote login client with NFSv4 forwarding
#

#
# Example usage:
# $ ksh sshnfs.ksh -o NFSURL=ssh+nfs://localhost//export/home/rmainz root@10.49.28.10 #
# $ ksh sshnfs.ksh -o NFSURL=nfs://localhost//export/home/rmainz root@10.49.20.207 #
# $ ksh sshnfs.ksh -o NFSURL=nfs://derfwpc5131//export/home/rmainz root@10.49.28.10 #
# $ ksh sshnfs.ksh -o NFSURL=ssh+nfs://derfwpc5131//export/home/rmainz -o SSHNFSJumphost=rmainz@derfwpc5131,roland.mainz@derfwnb8353 -J rmainz@derfwpc5131,roland.mainz@derfwnb8353 root@10.49.20.207
# $ ksh sshnfs.ksh -o NFSURL=ssh+nfs://derfwpc5131//export/home/rmainz target@fe80::d6f5:27ff:fe2b:8588%enp2s0
# $ ksh sshnfs.ksh -o NFSURL=ssh+nfs://root@derfwpc5131//export/home/rmainz root@10.49.28.56
# $ ksh sshnfs.ksh -o NFSServerSSHLoginName=root -o NFSURL=ssh+nfs://derfwpc5131//export/home/rmainz root@10.49.28.56
# $ SSHNFS_OPTIONS='-o NFSServerSSHLoginName=root -o NFSURL=ssh+nfs://derfwpc5131//export/home/rmainz' sshnfs.ksh root@10.49.28.56
#

#
# Written by Roland Mainz <roland.mainz@nrubsig.org>
#

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


function main
{
	set -o nounset
	typeset mydebug=false # fixme: should be "bool" for ksh93v
	integer i
	integer retval
	compound c

	#
	# Expand SSHNFS_OPTIONS before arguments given to sshnfs.ksh
	# By default we use IFS=$' \t\n' for argument splitting
	#
	typeset -a c.args=( ${SSHNFS_OPTIONS-} "$@" )

	for ((i=0 ; i < ${#c.args[@]} ; i++)) ; do
		if [[ "${c.args[i]}" == '-o' ]] ; then
			case "${c.args[i+1]-}" in
				~(Eli)NFSServerSSHLoginName=)
					# User name for SSH login to NFS server
					typeset c.nfsserver_ssh_login_name="${c.args[i+1]/~(Eli)NFSServerSSHLoginName=}"

					unset c.args[$i] c.args[$((i+1))]
					((i++))
					;;

				~(Eli)NFSURL=)
					unset c.nfs_server
					compound c.nfs_server
					typeset c.url="${c.args[i+1]/~(Eli)NFSURL=}"
					parse_sshnfs_url c.nfs_server "${c.url}" || return 1

					unset c.args[$i] c.args[$((i+1))]
					((i++))
					;;

				~(Eli)SSHNFSJumphost=)
					[[ ! -v c.ssh_jumphost_args ]] && typeset -a c.ssh_jumphost_args
					c.ssh_jumphost_args+=( "-J" "${c.args[i+1]/~(Eli)SSHNFSJumphost=}" )

					unset c.args[$i] c.args[$((i+1))]
					((i++))
					;;

				~(Eli)SSHNFSlocal_forward_port=)
					# command(1) prevents that the shell interpreter
					# exits if typeset produces a syntax error
					command integer c.local_forward_port="${c.args[i+1]/~(Eli)SSHNFSlocal_forward_port=}" || return 1

					unset c.args[$i] c.args[$((i+1))]
					((i++))
					;;
			esac
		fi
	done

	if [[ -v c.nfs_server ]] ; then
		if [[ ! -v c.nfs_server.port ]] ; then
			# use # default NFSv4 TCP port number (see
			# $ getent services nfs #)
			integer c.nfs_server.port=2049
		fi

		case "${c.nfs_server.scheme}" in
			'ssh+nfs')
				#
				# Find free local forwarding port...
				#

				# TCP port on destination machine where we forward the
				# NFS port from the server
				integer c.destination_nfs_port=33049

				# port on THIS machine
				if [[ ! -v c.local_forward_port ]] ; then
					integer c.local_forward_port

					(( i=34049 ))
					if ! netstat_find_next_free_local_tcp_port c.local_forward_port $i ; then
						print -u2 -f "%s: netstat_find_next_free_local_tcp_port failed.\n" "$0"
						return 1
					fi

					#
					# ... and adjust c.destination_nfs_port by the same offset
					# we do that so that multiple sshnfs.ksh logins to the same
					# machine do try to use the same ports on that machine
					#
					(( c.destination_nfs_port += ((c.local_forward_port-i) % 65535) ))

					# TCP ports below 1024 are reserved for the system, so stay away from them
					(( (c.destination_nfs_port <= 1024) && (c.destination_nfs_port += 34049) ))
				fi

				${mydebug} && printf $"debug: c.local_forward_port=%d, c.destination_nfs_port=%d\n" \
					c.local_forward_port \
					c.destination_nfs_port

				c.ssh_control_socket_name="/tmp/sshnfs_ssh-control-socket_logname${LOGNAME}_ppid${PPID}_pid$$"

				#
				# Find SSH login user name for NFS server
				#
				if [[ -v c.nfs_server.user ]] ; then
					typeset c.nfsserver_ssh_login_name="${c.nfs_server.user}"
				fi
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

				print -u2 -f $"# Linux: Use this to mount the directory:\n"
				print -u2 -f $"# $ mkdir /mnt_nfs\n"
				print -u2 -f $"# $ mount -vvv -t nfs -o vers=4.2,port=%d localhost:%s /mnt_nfs\n" \
					c.destination_nfs_port \
					"${c.nfs_server.uripath}"
				print -u2 -f $"\n"

				# note that OpenSSH on Windows (not Cygwin) will clear the screen
				# imediately after login
				print -u2 -f $"# Windows/ms-nfs41-client: Use this to mount the directory:\n"
				print -u2 -f $"# > %s --login\n" "C:\cygwin64\bin\bash.exe"
				print -u2 -f $"# $ /sbin/nfs_mount -o rw 'S' nfs://localhost:%d/%(url)q\n" \
					c.destination_nfs_port \
					"${c.nfs_server.uripath}"
				print -u2 -f $"\n\n"


				#
				# add NFS forwarding options to main ssh argument list
				#
				# Notes:
				# - We use aes128-cbc,aes128-ctr ciphers for better
				# throughput (see https://bash-prompt.net/guides/bash-ssh-ciphers/
				# for a benchmark) and lower latency, as NFS is
				# a bit latency-sensitive
				# - We turn compression off, as it incrases latency
				#
				c.args=(
					'-R' "${c.destination_nfs_port}:localhost:${c.local_forward_port}"
					'-o' 'ExitOnForwardFailure=yes'
					'-o' 'Compression=no'
					'-o' 'Ciphers=aes128-cbc,aes128-ctr'
					"${c.args[@]}"
				)
				;;
			'nfs')
				#
				# Validate configuration
				#
				if [[ -v c.ssh_jumphost_args ]] ; then
					print -u2 -f $"%s: Error: SSHNFSJumphost cannot be used for nfs://-URLs\n" "$0"
					return 2
				fi
				if [[ -v c.nfs_server.user ]] ; then
					print -u2 -f $"%s: Error: 'user' in URLs is not used in nfs://-URLs\n" "$0"
					return 2
				fi
				if [[ -v c.nfs_server.password ]] ; then
					print -u2 -f $"%s: Error: 'password' in URLs is not used in nfs://-URLs\n" "$0"
					return 2
				fi

				#
				# Guess a TCP port number which might be
				# free on the destination machine
				#
				integer myuid=$(id -u)
				integer mypid=$$ # used to circumvent ksh93 -n warning

				# TCP port on destination machine where we forward the
				# NFS port from the server
				integer c.destination_nfs_port=33049

				# try to adjust c.destination_nfs_port so that multiple sshnfs.ksh
				# sessions do intefere with each other
				# (16381 is a prime number)
				(( c.destination_nfs_port += (mypid+myuid+PPID) % 16381 ))

				print -u2 -f $"# Use this to mount the directory:\n"
				print -u2 -f $"# $ mkdir /mnt_nfs\n"
				print -u2 -f $"# $ mount -vvv -t nfs -o vers=4.2,port=%d localhost:%s /mnt_nfs\n" \
					c.destination_nfs_port \
					"${c.nfs_server.uripath}"

				#
				# add NFS forwarding options to main ssh argument list
				#
				# Notes:
				# - We use aes128-cbc,aes128-ctr ciphers for better
				# throughput (see https://bash-prompt.net/guides/bash-ssh-ciphers/
				# for a benchmark) and lower latency, as NFS is
				# a bit latency-sensitive
				# - We turn compression off, as it incrases latency
				#
				c.args=(
					'-R' "${c.destination_nfs_port}:${c.nfs_server.host}:${c.nfs_server.port}"
					'-o' 'ExitOnForwardFailure=yes'
					'-o' 'Compression=no'
					'-o' 'Ciphers=aes128-cbc,aes128-ctr'
					"${c.args[@]}"
				)
				;;
			*)
				print -u2 -f $"%s: Unknown URL scheme %q\n" "$0" "${c.nfs_server.scheme}"
				return 2
				;;
		esac
	fi

	# debug: print application data (compound c)
	${mydebug} && print -v c

	print -u2 -f $"# ssh login data for destination machine:\n"
	ssh "${c.args[@]}" ; (( retval=$? ))

	if [[ -v c.ssh_control_socket_name ]] ; then
		ssh \
			-S "${c.ssh_control_socket_name}" \
			-O 'exit' \
			"${c.nfsserver_ssh_login_name}@${c.nfs_server.host}"
	fi

	wait

	return $retval
}

#
# main
#
main "$@"
exit $?

# EOF.
