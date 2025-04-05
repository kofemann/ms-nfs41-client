#!/bin/ksh93

#
# MIT License
#
# Copyright (c) 2024-2025 Roland Mainz <roland.mainz@nrubsig.org>
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
# cygwinaccount2nfs4account.ksh93 - convert Cygwin user/group account
# info to Linux/UNIX NFSv4 server account data
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

function getent_local_domain_passwd
{
	integer res
	typeset passwdname="$1"

	#
	# first try local accounts and if getent does
	# not find anything do a (normal) domain lookup
	#
	# Cygwin getent uses '+' prefix to search for local
	# accounts only
	#
	getent passwd "+${passwdname}"
	(( res=$? ))

	if (( res == 2 )) ; then
		getent passwd "${passwdname}"
		(( res=$? ))
	fi

	return $res
}

function getent_local_domain_group
{
	integer res
	typeset groupname="$1"

	#
	# first try local accounts and if getent does
	# not find anything do a (normal) domain lookup
	#
	# Cygwin getent uses '+' prefix to search for local
	# accounts only
	#
	getent group "+${groupname}"
	(( res=$? ))

	if (( res == 2 )) ; then
		getent group "${groupname}"
		(( res=$? ))
	fi

	return $res
}

function getent_passwd2compound
{
	set -o nounset

	typeset username="$2"
	typeset leftover
	nameref data="$1" # output compound variable

	compound out

	# capture getent output
	out.stderr="${ { out.stdout="${ getent_local_domain_passwd "$username" ; (( out.res=$? )) ; }" ; } 2>&1 ; }"

	if [[ "${out.stderr}" != '' ]] || (( out.res != 0 )) ; then
		print -u2 -f $"%s: getent failed, msg=%q, res=%d\n" \
			"$0" "${out.stderr}" out.res
		return 1
	fi

	# ~(E) is POSIX extended regular expression matching (instead
	# of shell pattern), "x" means "multiline", "l" means "left
	# anchor", "r" means "right anchor"
	leftover="${out.stdout/~(Elrx)
		(.+?)			# login name
		:(.+?)			# encrypted passwd
		:(.+?)			# uid
		:(.+?)			# gid
		:(.+?)			# comment
		:(.+?)			# homedir
		(?::(.+?))?		# shell (optional)
		/X}"

	# All parsed data should be captured via eregex in .sh.match - if
	# there is anything left (except the 'X') then the input string did
	# not properly match the eregex
	[[ "$leftover" == 'X' ]] ||
		{ print -u2 -f $"%s: Parser error, leftover=%q\n" \
			"$0" "$leftover" ; return 1 ; }

	data.getent_username="$username"
	data.login_name="${.sh.match[1]}"
	data.encrypted_passwd="${.sh.match[2]}"
	data.uid="${.sh.match[3]}"
	data.gid="${.sh.match[4]}"
	data.comment="${.sh.match[5]}"
	data.homedir="${.sh.match[6]}"
	data.shell="${.sh.match[7]}"

	return 0
}

function getent_group2compound
{
	set -o nounset

	typeset groupname="$2"
	typeset leftover
	nameref data="$1" # output compound variable

	compound out

	# capture getent output
	out.stderr="${ { out.stdout="${ getent_local_domain_group "$groupname" ; (( out.res=$? )) ; }" ; } 2>&1 ; }"

	if [[ "${out.stderr}" != '' ]] || (( out.res != 0 )) ; then
		print -u2 -f $"%s: getent failed, msg=%q, res=%d\n" \
			"$0" "${out.stderr}" out.res
		return 1
	fi

	# ~(E) is POSIX extended regular expression matching (instead
	# of shell pattern), "x" means "multiline", "l" means "left
	# anchor", "r" means "right anchor"
	leftover="${out.stdout/~(Elrx)
		(.+?):			# group
		(.+?):			# encrypted passwd
		(.+?):			# gid
		(?:(.+?))?		# userlist
		/X}"

	# All parsed data should be captured via eregex in .sh.match - if
	# there is anything left (except the 'X') then the input string did
	# not properly match the eregex
	[[ "$leftover" == 'X' ]] ||
		{ print -u2 -f $"%s: Parser error, leftover=%q\n" \
			"$0" "$leftover" ; return 1 ; }

	data.getent_groupname="$groupname"
	data.group_name="${.sh.match[1]}"
	data.encrypted_passwd="${.sh.match[2]}"
	data.gid="${.sh.match[3]}"
	[[ -v .sh.match[4] ]] && data.userlist="${.sh.match[4]}"

	return 0
}


function accountdata2linuxscript
{
	set -o nounset

	typeset os="$1"
	nameref accountdata=$2
	typeset gidlist=''
	typeset sidname

	#
	# first start with the groups, as useradd wants a group to be there
	#
	integer i

	printf '\n\n#\n'
	printf '# Group data:\n'
	printf '#\n'

	for ((i=0 ; i < ${#accountdata.group_list[@]} ; i++ )) ; do
		nameref currgrp=accountdata.group_list[$i]

		#
		# Cygwin was Win32 SID values in "encrypted_passwd",
		# we use this to reject groups which have special
		# functions in Win32
		sidname="${currgrp.encrypted_passwd}"
		# check if "sidname" is realy a Win32 SID
		if [[ "$sidname" == ~(El)S-1-[[:digit:]]+-[[:digit:]]+ ]] ; then
			if [[ "$sidname" != ~(Elr)S-1-5-21-.+ ]] ; then
				continue
			fi
		fi

		printf 'groupadd -g %s %q\n' "${currgrp.gid}" "${currgrp.group_name}"

		[[ "$gidlist" != '' ]] && gidlist+=','
		gidlist+="${currgrp.gid}"
	done

	#
	# user data itself
	#
	nameref curruser=accountdata.user

	printf '\n\n#\n'
	printf '# User data:\n'
	printf '#\n'

	case "$os" in
		'linux')
			printf 'mkdir -p %q\n' "${curruser.homedir}"
			printf 'useradd -u %s -g %s -G %q -s %q %q\n' \
				"${curruser.uid}" \
				"${curruser.gid}" \
				"${gidlist}" \
				"${curruser.shell}" \
				"${curruser.login_name}"
			printf 'chown %q %q\n' \
				"${curruser.uid}:${curruser.gid}" \
				"${curruser.homedir}"
		;;
		'solaris' | 'illumos')
			printf 'mkdir -p %q\n' "/export/${curruser.homedir}"
			printf 'printf "%s\\tlocalhost:/export/home/%s\\n" >>"/etc/auto_home"\n' \
				"${curruser.login_name}" \
				"${curruser.login_name}"
			printf 'useradd -u %s -g %s -G %q -s %q %q\n' \
				"${curruser.uid}" \
				"${curruser.gid}" \
				"${gidlist}" \
				"${curruser.shell}" \
				"${curruser.login_name}"
			printf 'chown %q %q\n' \
				"${curruser.uid}:${curruser.gid}" \
				"/export/${curruser.homedir}"
		;;
	esac

	return 0
}

function print_nfs4_server_config
{
	nameref cfg=$1

	# fixme: we need to figure out the real NFSv4 idmapping domain of the client
	printf '\n\n#\n'
	printf '# NFSv4 server config:\n'
	printf '#\n'

	printf '# turn idmapper on, even for AUTH_SYS\n'
	printf '{\n'
	printf '\tprintf "[General]\\n"\n'
	printf '\tprintf "Domain = %s\\n"\n' "GLOBAL.LOC"
	printf '} >>"/etc/idmapd.conf"\n'

	printf 'printf "options nfsd nfs4_disable_idmapping=N\\noptions nfs nfs4_disable_idmapping=N\\n" >>"/etc/modprobe.d/nfs.conf"\n'
	printf 'printf "NEED_IDMAPD=yes\\n" >>"/etc/default/nfs-common"\n'

	return 0
}

function convert_curruser2linuxscript
{
	nameref cfg=$1
	shift

	compound account_data
	compound account_data.user
	compound -a account_data.group_list
	integer i=0
	typeset -a group_list

	getent_passwd2compound account_data.user "$(id -u)"

	group_list=( $(id -G) )

	#
	# Collect group information into "account_data" CPV
	#
	for ((i=0 ; i < ${#group_list[@]} ; i++ )) ; do
		getent_group2compound account_data.group_list[$i] "${group_list[$i]}"
	done

	${cfg.debug} && print -u2 -v account_data

	#
	# Generate Linux script from collected "account_data"
	#
	accountdata2linuxscript "${cfg.os}" account_data

	#
	# Print NFSv4 server config
	#
	if [[ "${cfg.os}" == 'linux' ]] ; then
		print_nfs4_server_config cfg
	fi

	#
	# Done
	#
	printf '\n# Done.\n'

	return 0
}

function convert_givenuser2linuxscript
{
	nameref cfg=$1
	shift

	typeset username="$1"

	compound account_data
	compound account_data.user
	compound -a account_data.group_list
	integer i=0
	typeset -a group_list

	getent_passwd2compound account_data.user "$username"

	compound out

	#
	# Get group data from Directory Server
	#

	#
	# query DS via powershell
	#
	out.stderr="${ { out.stdout="${
		queryuser="$username" powershell -Command '(New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=$("$env:queryuser")))")).FindOne().GetDirectoryEntry().memberOf'
		(( out.res=$? )) ; }" ; } 2>&1 ; }"

	if [[ "${out.stderr}" != '' ]] || (( out.res != 0 )) ; then
		print -u2 -f $"%s: powershell querying groups from DS failed, msg=%q, res=%d\n" \
			"$0" "${out.stderr}" out.res
		return 1
	fi

	#
	# Parse LDAP-style output
	#
	dummy="${out.stdout//~(E)CN=(.+?),/dummy}"
	${cfg.debug} && printf 'dummy=%q\n' "$dummy"

	for ((i=0 ; i < ${#.sh.match[1][@]} ; i++)) ; do
		group_list+=( "${.sh.match[1][$i]}" )
	done

	#
	# Collect group information into "account_data" CPV
	#
	for ((i=0 ; i < ${#group_list[@]} ; i++ )) ; do
		getent_group2compound account_data.group_list[$i] "${group_list[$i]}"
	done

	${cfg.debug} && print -u2 -v account_data

	#
	# Generate Linux script from collected "account_data"
	#
	accountdata2linuxscript "${cfg.os}" account_data

	#
	# Print NFSv4 server config
	#
	print_nfs4_server_config cfg

	#
	# Done
	#
	printf '\n# Done.\n'

	return 0
}

function main
{
	set -o nounset

	# fixme: Need better text layout for $ cygwinaccount2nfs4account --man #
	typeset -r cygwinaccount2nfs4account_usage=$'+
	[-?\n@(#)\$Id: cygwinaccount2nfs4account (Roland Mainz) 2025-04-05 \$\n]
	[-author?Roland Mainz <roland.mainz@nrubsig.org>]
	[+NAME?cygwinaccount2nfs4account - convert Cygwin user/group account
		info to Linux/UNIX NFSv4 server account data]
	[+DESCRIPTION?\bcygwinaccount2nfs4account\b convert Cygwin user/group account
		info to Linux/UNIX NFSv4 server account data.]
	[D:debug?Enable debugging.]
	[O:os?Operating system, either \blinux\b, \bsolaris\b or
		\billumos\b).]:[os]

	--man

	[+SEE ALSO?\bksh93\b(1),\bms-nfs41-client\b(1),\bnfs\b(5)]
	'

	compound c
	typeset -a c.args
	integer saved_optind_m1	# saved OPTIND-1

	c.args=( "$@" )

	typeset c.debug=false

	#
	# Argument parsing
	#
	while getopts -a "${progname}" "${cygwinaccount2nfs4account_usage}" OPT "${c.args[@]}" ; do
		case "${OPT}" in
			'D')
				c.debug=true
				;;
                        'O')
				typeset c.os="${OPTARG}"
				;;
			*)
				usage "${progname}" "${cygwinaccount2nfs4account_usage}"
				return $?
				;;
		esac
	done

	(( saved_optind_m1=OPTIND-1 ))

	# remove options we just parsed from c.args
	for ((i=0 ; i < saved_optind_m1 ; i++)) ; do
		unset c.args[$i]
	done

	if [[ ! -v c.os ]] ; then
		print -u2 -f $"%s: Require -O <operating-system>\n" "${progname}"
		return 1
	fi

	if [[ "${c.os}" != ~(Elr)(linux|solaris|illumos) ]] ; then
		print -u2 -f $"%s: Unsuppoted -O value %q, supported are 'linux', 'solaris', 'illumos'\n" \
			"${progname}" \
			"${c.os}"
		return 1
	fi

	#
	# c.args mighth be a sparse array (e.g. "([1]=aaa [2]=bbb [4]=ccc)")
	# right now after we removed processed options/arguments.
	# For easier processing below we "reflow" the array back to a
	# normal linear layout (e.g. ([0]=aaa [1]=bbb [2]=ccc)
	#
	c.args=( "${c.args[@]}" )

	#
	# ToDo:
	# - Command-line options
	# - Convert current user+groups to Linux bash script [done]
	# - Convert current user+groups to /etc/passwd+/etc/group lines
	# - Convert given user+groups to Linux bash script
	# - Convert given user+groups to /etc/passwd+/etc/group lines
	#

	if (( ${#c.args[@]} == 0 )) ; then
		print -u2 -f $"# Converting current user\n"
		convert_curruser2linuxscript c "$@"
	else
		print -u2 -f $"# Converting given user\n"
		convert_givenuser2linuxscript c "$@"
	fi

	return 2
}

#
# main
#
builtin cat
builtin id
builtin mkdir
builtin basename

typeset progname="${ basename "${0}" ; }"

main "$@"
exit $?

# EOF.
