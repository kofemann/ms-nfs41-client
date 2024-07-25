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
# cygwinaccount2nfs4account.ksh93 - transfer Cygwin user/group account
# info to Linux/UNIX NFSv4 server account data
#

#
# Written by Roland Mainz <roland.mainz@nrubsig.org>
#

function getent_passwd2compound
{
	set -o nounset

	typeset username="$2"
	typeset leftover
	nameref data="$1" # output compound variable

	compound out

	# capture getent output
	out.stderr="${ { out.stdout="${ getent passwd "$username" ; (( out.res=$? )) ; }" ; } 2>&1 ; }"

	if [[ "${out.stderr}" != '' ]] || (( out.res != 0 )) ; then
		print -u2 $"%s: getent failed, msg=%q, res=%d\n" \
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
	out.stderr="${ { out.stdout="${ getent group "$groupname" ; (( out.res=$? )) ; }" ; } 2>&1 ; }"

	if [[ "${out.stderr}" != '' ]] || (( out.res != 0 )) ; then
		print -u2 $"%s: getent failed, msg=%q, res=%d\n" \
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

	nameref accountdata=$1
	typeset gidlist=''
	typeset sidname

	#
	# first start with the groups, as useradd wants a group to be there
	#
	integer i

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

	return 0
}


function convert_curruser2linuxscript
{
	compound account_data
	compound account_data.user
	compound -a account_data.group_list
	integer i=0
	typeset currgroup

	getent_passwd2compound account_data.user "$(id -u)"

	for currgroup in $(id -G) ; do
		getent_group2compound account_data.group_list[$((i++))] "$currgroup"
	done

	print -v account_data

	accountdata2linuxscript account_data

	# fixme: we need to figure out the real NFSv4 idmapping domain of the client
	printf 'printf "Domain = GLOBAL.LOC\\n" >>"/etc/idmapd.conf"\n'

	printf 'printf "options nfsd nfs4_disable_idmapping=N\\noptions nfs nfs4_disable_idmapping=N\\n" >>"/etc/modprobe.d/nfs.conf"\n'
	printf 'printf "NEED_IDMAPD=yes\\n" >>"/etc/default/nfs-common"\n'

	return 0
}


#
# ToDo:
# - Command-line options
# - Convert current user+groups to Linux bash script [done]
# - Convert current user+groups to /etc/passwd+/etc/group lines
# - Convert given user+groups to Linux bash script
# - Convert given user+groups to /etc/passwd+/etc/group lines
#
function main
{
	convert_curruser2linuxscript "$@"
	return $?
}

builtin id

main "$@"
return $?


# EOF.
