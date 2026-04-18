#!/bin/ksh93

#
# MIT License
#
# Copyright (c) 2023-2026 Roland Mainz <roland.mainz@nrubsig.org>
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
# cygwin_idmapper.ksh - simple idmapper shell script which
# converts Windows { user, group, cygwin_uid, cygwin_gid } account information
# from/to NFSv4.1 { owner, owner_group, uid, gid }
#
# Input is the query mode { lookup_user_by_localname, lookup_group_by_localgroup,
# lookup_user_by_nfsserver_owner, lookup_group_by_nfsserver_owner_group }, output
# is a ksh93 compound variable with both Windows and NFS account information.
#

#
# Written by Roland Mainz <roland.mainz@nrubsig.org>
#

function setup_windows_builtin_accounts
{
	nameref c=$1

	#
	# Windows uses localised user and group names,
	# e.g. on a German Windows the group "None" is called "Kein" etc.
	#
	# Cygwin allows to lookup users&&groups by their SID with
	# /usr/bin/getent, so we use that to get the localised user/group
	# name.
	# Alternatively powershell can be used like this:
	# ---- snip ----
	# (New-Object System.Security.Principal.SecurityIdentifier \
	#   "S-1-5-21-3286904461-661230000-4220857270-513").Translate( [System.Security.Principal.NTAccount]).Value
	# ---- snip ----
	#

	#
	# Windows localised principals are (list incomplete)
	#
	# "SYSTEM" (SID is 'S-1-5-18'):
	#   EN: SYSTEM@NT AUTHORITY
	#   DE: SYSTEM@NT-AUTORIT\xC3\x84T
	#   FR: Syst\xC3\xA8me@AUTORIT\xC3\x89 NT
	#
	# "Administrator" (built-in local user, SID is "${machine_sid}-500"):
	#   EN: Administrator@<COMPUTERNAME>
	#   DE: Administrator@<COMPUTERNAME>
	#   FR: Administrateur@<COMPUTERNAME>
	#
	# "Administrators" (built-in local group, SID is 'S-1-5-32-544'):
	#   EN: Administrators@BUILTIN
	#   DE: Administratoren@VORDEFINIERT
	#   FR: Administrateurs@BUILTIN
	#
	# "Users" (built-in local group, SID is 'S-1-5-32-545'):
	#   EN: Users@BUILTIN
	#   DE: Benutzer@VORDEFINIERT
	#   FR: Utilisateurs@BUILTIN
	#
	# "None" (primary group; SID is "${machine_sid}-513"):
	#   EN: None@<COMPUTERNAME>
	#   DE: Kein@<COMPUTERNAME>
	#   FR: Aucun@<COMPUTERNAME>
	#

	set -o nounset

	typeset s

	# fixme: Different Windows versions use different machine SIDs
	# Windows 10+Windows Server 2019 use
	# "S-1-5-21-3286904461-661230000-4220857270", but other Windows
	# versions use different values
	typeset machine_sid="$(mkgroup -l | sed -n 's/[^:]*:\(S-[-0-9]*\)-513:.*$/\1/p')"
	if [[ "$machine_sid" != ~(El)S-1-5-21- ]] ; then
		print -u2 -f "%s: Unexpected machine SID %q\n" \
			"$0" "$machine_sid"
		exit 1
	fi

	#
	# build user list
	#
	compound -r -A windows_builtin_user_list=(
		['WIN_CREATOR_OWNER']=(
			sid='S-1-3-0'
			localuid=66304 # Static localgid, because it will not change
			nfsuid=66304
			typeset -A localised_names=(
				['windows/en']=$'CREATOR OWNER@'
				['windows/de']=$'ERSTELLER-BESITZER@'
				['windows/fr']=$'CREATEUR PROPRIETAIRE@'
				['freebsd']='CREATOR OWNER@'
				['solaris']='CREATOR OWNER@'
				['linux']='CREATOR OWNER@'
			)
		)
		['SYSTEM']=(
			sid='S-1-5-18'
			localuid=18 # Static localuid, because it will not change
			nfsuid=18
			typeset -A localised_names=(
				['windows/en']=$'SYSTEM@NT AUTHORITY'
				['windows/de']=$'SYSTEM@NT-AUTORIT\xC3\x84T'
				['windows/fr']=$'Syst\xC3\xA8me@AUTORIT\xC3\x89 NT'
				['freebsd']="SYSTEM@${idmap_config.nfsdomain}"
				['solaris']="SYSTEM@${idmap_config.nfsdomain}"
				['linux']="SYSTEM@${idmap_config.nfsdomain}"
			)
		)
		['Administrator']=(
			sid="${machine_sid}-500"
			# localuid will be obtained via getent(1)
			nfsuid=197108
			typeset -A localised_names=(
				['windows/en']="Administrator@${COMPUTERNAME}"
				['windows/de']="Administrator@${COMPUTERNAME}"
				['windows/fr']="Administrateur@${COMPUTERNAME}"
				['freebsd']="Administrator@${idmap_config.nfsdomain}"
				['solaris']="Administrator@${idmap_config.nfsdomain}"
				['linux']="Administrator@${idmap_config.nfsdomain}"
			)
		)
	)

	#
	# build group list
	#
	compound -r -A windows_builtin_group_list=(
		['WIN_CREATOR_GROUP']=(
			sid='S-1-3-1'
			localgid=66305 # Static localgid, because it will not change
			nfsgid=66305
			typeset -A localised_names=(
				['windows/en']=$'CREATOR GROUP@'
				['windows/de']=$'ERSTELLERGRUPPE@'
				['windows/fr']=$'GROUPE CR\xC3\x89ATEUR@'
				['freebsd']='CREATOR GROUP@'
				['solaris']='CREATOR GROUP@'
				['linux']='CREATOR GROUP@'
			)
		)
		['WIN_EVERYONE']=(
			sid='S-1-1-0'
			localgid=-1 # No gid for this
			nfsgid=-1
			typeset -A localised_names=(
				['windows/en']=$'Everyone@'
				['windows/de']=$'Jeder@'
				['windows/fr']=$'Tout le monde@'
				['freebsd']='EVERYONE@'
				['solaris']='EVERYONE@'
				['linux']='EVERYONE@'
			)
		)
		['SYSTEM']=(
			sid='S-1-5-18'
			localgid=18 # Static localgid, because it will not change
			nfsgid=18
			typeset -A localised_names=(
				['windows/en']=$'SYSTEM@NT AUTHORITY'
				['windows/de']=$'SYSTEM@NT-AUTORIT\xC3\x84T'
				['windows/fr']=$'Syst\xC3\xA8me@AUTORIT\xC3\x89 NT'
				['freebsd']="SYSTEM@${idmap_config.nfsdomain}"
				['solaris']="SYSTEM@${idmap_config.nfsdomain}"
				['linux']="SYSTEM@${idmap_config.nfsdomain}"
			)
		)
		['Administrators']=(
			sid='S-1-5-32-544'
			localgid=544 # Static localgid, because it will not change
			nfsgid=544
			typeset -A localised_names=(
				['windows/en']="Administrators@BUILTIN"
				['windows/de']="Administratoren@VORDEFINIERT"
				['windows/fr']='Administrateurs@BUILTIN'
				['freebsd']="Administrators@${idmap_config.nfsdomain}"
				['solaris']="Administrators@${idmap_config.nfsdomain}"
				['linux']="Administrators@${idmap_config.nfsdomain}"
			)
		)
		['Users']=(
			sid='S-1-5-32-545'
			localgid=545 # Static localgid, because it will not change
			nfsgid=545
			typeset -A localised_names=(
				['windows/en']="Users@BUILTIN"
				['windows/de']="Benutzer@VORDEFINIERT"
				['windows/fr']='Utilisateurs@BUILTIN'
				['freebsd']="Users@${idmap_config.nfsdomain}"
				['solaris']="Users@${idmap_config.nfsdomain}"
				['linux']="Users@${idmap_config.nfsdomain}"
			)
		)
		['None']=(
			sid="${machine_sid}-513"
			# localgid will be obtained via getent(1)
			nfsgid=197121
			typeset -A localised_names=(
				['windows/en']="None@${idmap_config.nfsdomain}"
				['windows/de']="Kein@${idmap_config.nfsdomain}"
				['windows/fr']="Aucun@${idmap_config.nfsdomain}"
				['freebsd']="None@${idmap_config.nfsdomain}"
				['solaris']="None@${idmap_config.nfsdomain}"
				['linux']="None@${idmap_config.nfsdomain}"
			)
		)
	)


	#
	# Process Windows builtin users
	#
	for s in "${!windows_builtin_user_list[@]}" ; do
		nameref n=windows_builtin_user_list["$s"]

		compound gpc
		parse_getent_passwd2compound gpc "$(getent passwd ${n.sid})"
		if (( $? == 0 )) ; then
			integer localuid

			compound nt_parse
			parse_ntaccount nt_parse "$(sed -E 's/U-([^,]+).+/\1/' <<<"${gpc.comment}")"

			if [[ -v n.localuid ]] ; then
				(( localuid=n.localuid ))
			else
				(( localuid=gpc.uid ))
			fi

			c.localusers+=(
				["$s"]=(
					localaccountname="${nt_parse.user}@${nt_parse.domain}"
					localuid=${localuid}
					nfsuid=${n.nfsuid}
					nfsowner=${n.localised_names[${idmap_config.servertype}]}
				)
			)
		fi
	done

	#
	# Process Windows builtin groups
	#
	for s in "${!windows_builtin_group_list[@]}" ; do
		nameref n=windows_builtin_group_list["$s"]

		# (we use getent passwd here because getent group does not give us a domain name)
		compound gpc
		# SID 'S-1-1-0' is a special case because Cygwin /usr/bin/getent group/passwd cannot look it up
		if [[ "${n.sid}" == 'S-1-1-0' ]] ; then
			# NOTE: Using powershell is slow, do we use system32/whoami
			typeset everyone_name dummy1
			#/cygdrive/c/Windows/System32/WindowsPowerShell/v1.0/powershell -Command $'(Get-CimInstance Win32_Account -Filter "SID=\'S-1-1-0\'").Name' | IFS=$' \t\n\r' read everyone_name
			/cygdrive/c/Windows/system32/whoami /groups | grep -a -F 'S-1-1-0' | IFS=$' \t\n\r' read everyone_name dummy1
			parse_getent_passwd2compound gpc "${everyone_name}:*:65550:65550:U-\\${everyone_name},S-1-1-0:/:/sbin/nologin"
		else
			parse_getent_passwd2compound gpc "$(getent passwd ${n.sid})"
		fi
		if (( $? == 0 )) ; then
			integer localgid

			compound nt_parse
			parse_ntaccount nt_parse "$(sed -E 's/U-([^,]+).+/\1/' <<<"${gpc.comment}")"

			if [[ -v n.localgid ]] ; then
				(( localgid=n.localgid ))
			else
				# use gpc.uid because we used getent passwd above
				(( localgid=gpc.uid ))
			fi

			c.localgroups+=(
				["$s"]=(
					localgroupname="${nt_parse.user}@${nt_parse.domain}"
					localgid=${localgid}
					nfsgid=${n.nfsgid}
					nfsownergroup=${n.localised_names[${idmap_config.servertype}]}
				)
			)
		fi
	done

	return 0
}

function setup_site_system_accounts
{
	nameref c=$1

	c.localusers+=(
		#
		# System accounts
		#
		["root"]=(
			localaccountname="root@${COMPUTERNAME}"
			localuid=0
			nfsowner="root@${idmap_config.nfsdomain}"
			nfsuid=0
		)
		["nobody"]=(
			localaccountname="nobody@${COMPUTERNAME}"
			localuid=65534
			nfsowner="nobody@${idmap_config.nfsdomain}"
			nfsuid=65534
		)
	)

	c.localgroups+=(
		#
		# System accounts
		#
		["root"]=(
			localgroupname="root@${COMPUTERNAME}"
			localgid=0
			nfsownergroup="root@${idmap_config.nfsdomain}"
			nfsgid=0
		)
		["nogroup"]=(
			localgroupname="nogroup@${COMPUTERNAME}"
			localgid=65534
			nfsownergroup="nogroup@${idmap_config.nfsdomain}"
			nfsgid=65534
		)
		#
		# Group "sys" required for Solaris/Illumos nfsd
		#
		["sys"]=(
			localgroupname="sys@${COMPUTERNAME}"
			localgid=3
			nfsownergroup="sys@${idmap_config.nfsdomain}"
			nfsgid=3
		)
		#
		# Group "nobody" required for Solaris/Illumos nfsd
		# Question is why "nobody" shows up in a "group" idmapper lookup
		#
		["nobody"]=(
			localgroupname="nobody@${COMPUTERNAME}"
			localgid=65534
			nfsownergroup="nobody@${idmap_config.nfsdomain}"
			nfsgid=65534
		)
	)

	return 0
}

function setup_site_accounts_lab_example1
{
	nameref c=$1

	c.localusers+=(
		#
		# Site-specific users
		#
		["roland_mainz"]=(
			localaccountname="roland_mainz@${COMPUTERNAME}"
			localuid=197608
			nfsowner="rmainz@${idmap_config.nfsdomain}"
			nfsuid=1616
		)
		["siegfried_wulsch"]=(
			localaccountname="siegfried_wulsch@${COMPUTERNAME}"
			localuid=197609
			nfsowner="swulsch@${idmap_config.nfsdomain}"
			nfsuid=1818
		)
	)

	c.localgroups+=(
		#
		# Site-specific groups
		#
		["rmainz"]=(
			localgroupname="rmainz@${COMPUTERNAME}"
			localgid=1616
			nfsownergroup="rmainz@${idmap_config.nfsdomain}"
			nfsgid=1616
		)
		["swulsch"]=(
			localgroupname="swulsch@${COMPUTERNAME}"
			localgid=1818
			nfsownergroup="swulsch@${idmap_config.nfsdomain}"
			nfsgid=1818
		)
	)

	return 0
}

function setup_site_accounts_rovemadomain_example2
{
	nameref c=$1

	c.localusers+=(
		#
		# Site-specific users
		#
		["roland.mainz"]=(
			localaccountname="roland.mainz@GLOBAL"
			localuid=1059696
			nfsowner="rmainz@${idmap_config.nfsdomain}"
			nfsuid=1616
		)
		["Siegfried.Wulsch"]=(
			localaccountname="Siegfried.Wulsch@GLOBAL"
			localuid=1050083
			nfsowner="swulsch@${idmap_config.nfsdomain}"
			nfsuid=1818
		)
	)

	c.localgroups+=(
		#
		# Site-specific groups
		#
		['Domain Users']=(
			localgroupname="Domain Users@GLOBAL"
			localgid=1049089
			nfsownergroup="Domain_Users@global.loc"
			nfsgid=1049089
		)
	)

	return 0
}

function parse_ntaccount
{
	nameref c=$1
	typeset raw_string="$2"

	typeset stripped="${raw_string#*U-}"

	stripped="${stripped%%,*}"

	c.domain="${stripped%\\*}"
	c.user="${stripped#*\\}"

	return 0
}

function parse_getent_passwd2compound
{
	set -o nounset

	typeset getent_passwd_string="$2"
	typeset leftover
	nameref data="$1" # output compound variable

	# ~(E) is POSIX extended regular expression matching (instead
	# of shell pattern), "x" means "multiline", "l" means "left
	# anchor", "r" means "right anchor"
	leftover="${getent_passwd_string/~(Elrx)
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

	data.login_name="${.sh.match[1]}"
	data.encrypted_passwd="${.sh.match[2]}"
	data.uid="${.sh.match[3]}"
	data.gid="${.sh.match[4]}"
	data.comment="${.sh.match[5]}"
	data.homedir="${.sh.match[6]}"
	data.shell="${.sh.match[7]}"

	return 0
}

function parse_getent_group2compound
{
	set -o nounset

	typeset getent_group_string="$2"
	typeset leftover
	nameref data="$1" # output compound variable

	# ~(E) is POSIX extended regular expression matching (instead
	# of shell pattern), "x" means "multiline", "l" means "left
	# anchor", "r" means "right anchor"
	leftover="${getent_group_string/~(Elrx)
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

	data.group_name="${.sh.match[1]}"
	data.encrypted_passwd="${.sh.match[2]}"
	data.gid="${.sh.match[3]}"
	[[ -v .sh.match[4] ]] && data.userlist="${.sh.match[4]}"

	return 0
}

function getent_local_domain_passwd
{
	integer res
	typeset arg="$1"

	typeset username="${arg%%@*}"
	typeset domainname="${arg#*@}"

	#
	# lookup local accounts
	#
	# Notes:
	# - Cygwin getent uses "+" prefix to search for local
	# accounts only
	# - Cygwin getent uses "U-" prefix to pass the input string to
	# |LookupAccountNameA()| directly
	#
	getent passwd "U-${domainname}\\${username}"
	(( res=$? ))

	return $res
}

function getent_local_domain_group
{
	integer res
	typeset arg="$1"

	typeset groupname="${arg%%@*}"
	typeset domainname="${arg#*@}"

	#
	# lookup local accounts
	#
	# Notes:
	# - Cygwin getent uses "+" prefix to search for local
	# accounts only
	# - Cygwin getent uses "U-" prefix to pass the input string to
	# |LookupAccountNameA()| directly
	#
	getent group "U-${domainname}\\${groupname}"
	(( res=$? ))

	return $res
}

function getent_nfs_domain_passwd
{
	integer res
	typeset arg="$1"

	if [[ "${arg}" == ~(Elr)[[:digit:]]+ ]] ; then
		getent passwd "${arg}"
		(( res=$? ))
		return $res
	fi

	typeset username="${arg%%@*}"
	typeset domainname="${arg#*@}"

	if [[ "${domainname}" == "${idmap_config.nfsdomain}" ]] ; then
		getent passwd "${username}"
		(( res=$? ))
	else
		getent passwd "${domainname}+${username}"
		(( res=$? ))
	fi

	return $res
}

function getent_nfs_domain_group
{
	integer res
	typeset arg="$1"

	if [[ "${arg}" == ~(Elr)[[:digit:]]+ ]] ; then
		getent group "${arg}"
		(( res=$? ))
		return $res
	fi

	typeset groupname="${arg%%@*}"
	typeset domainname="${arg#*@}"

	if [[ "${domainname}" == "${idmap_config.nfsdomain}" ]] ; then
		getent group "${groupname}"
		(( res=$? ))
	else
		getent group "${domainname}+${groupname}"
		(( res=$? ))
	fi

	return $res
}

function main_dispatch
{
	set -o nounset

	#
	# global variables for this script
	# (stored in compound variable so we
	# can do a $ print -u2 -v c # for debugging)
	#
	compound c=(
		compound -A localusers
		compound -A localgroups
	)

	typeset s
	typeset stdout

	(( $# > 0 )) && c.mode="$1"
	(( $# > 1 )) && c.idmapconfigname="$2"
	if (( $# > 2 )) ; then
		# strip '"' characters (for Cygwin 3.3 compatibility)
		# note that "${2-//..." does NOT work!
		c.name="${3//\"/}"
	fi


	if [[ ! -v COMPUTERNAME ]] ; then
		printf -u2 -f $"ERROR: COMPUTERNAME var not set\n"
		export COMPUTERNAME="$(uname -n | tr '[:lower:]' '[:upper:]')"
		return 1
	fi

	setup_windows_builtin_accounts c
	setup_site_system_accounts c
	setup_site_accounts_lab_example1 c
	#setup_site_accounts_rovemadomain_example2 c

	case "${c.mode-}" in
		'lookup_user_by_localname')
			#
			# Try static info
			#
			if [[ "${c.name}" == ~(Elr)[[:digit:]]+ ]] ; then
				for s in "${!c.localusers[@]}" ; do
					if (( c.localusers["$s"].localuid == c.name )) ; then
						print -v c.localusers["$s"]
						return 0
					fi
				done
				# getent passwd accepts numeric uids too, so continue below
			else
				for s in "${!c.localusers[@]}" ; do
					if [[ "${c.localusers["$s"].localaccountname}" == "${c.name}" ]] ; then
						print -v c.localusers["$s"]
						return 0
					fi
				done
			fi

			#
			# try getent passwd
			#
			compound pgec # parsed getent data compound var
			compound gec # getent compound var

			stdout="${ getent_local_domain_passwd "${c.name}" };"
			if (( $? == 0 )) && [[ "${stdout}" != '' ]]; then
				parse_getent_passwd2compound pgec "${stdout}"
				if (( $? == 0 )) ; then
					if [[ "${pgec.uid-}" == ~(Elr)[[:digit:]]+ ]] ; then
						compound nt_parsed
						parse_ntaccount nt_parsed "${pgec.comment}"
						gec.localaccountname="${nt_parsed.user}@${nt_parsed.domain}"
						gec.nfsowner="${nt_parsed.user}@${idmap_config.nfsdomain}"
						(( gec.localuid=pgec.uid ))
						(( gec.nfsuid=pgec.uid ))
						print -v gec
						return 0
					else
						print -u2 -f "cygwin_idmapper.ksh(cfg=%q): getent passwd %q returned garbage %q.\n" \
							"${c.idmapconfigname-}" \
							"${c.name}" "${gec.localuid-}"
						return 1
					fi
				fi
			fi

			print -u2 -f "cygwin_idmapper.ksh(cfg=%q): Account %q not found.\n" \
				"${c.idmapconfigname-}" "${c.name}"
			return 1
			;;
		'lookup_group_by_localgroup')
			#
			# Try static info
			#
			if [[ "${c.name}" == ~(Elr)[[:digit:]]+ ]] ; then
				for s in "${!c.localgroups[@]}" ; do
					if (( c.localgroups["$s"].localgid == c.name )) ; then
						print -v c.localgroups["$s"]
						return 0
					fi
				done
				# getent group accepts numeric gids too, so continue below
			else
				for s in "${!c.localgroups[@]}" ; do
					if [[ "${c.localgroups["$s"].localgroupname}" == "${c.name}" ]] ; then
						print -v c.localgroups["$s"]
						return 0
					fi
				done
			fi

			#
			# try getent group
			#
			compound pgec # parsed getent data compound var
			compound gec # getent compound var
			stdout="${ getent_local_domain_group "${c.name}" ;}"
			if (( $? == 0 )) && [[ "${stdout}" != '' ]] ; then
				parse_getent_group2compound pgec "${stdout}"
				if (( $? == 0 )) ; then
					if [[ "${pgec.gid-}" == ~(Elr)[[:digit:]]+ ]] ; then
						if [[ "${pgec.group_name}" == *"+"* ]]; then
							domain="${pgec.group_name%%+*}"
							user="${input#*+}"
						else
							# No '+' found, fallback to the local machine name
							domain="${COMPUTERNAME}"
							user="${pgec.group_name}"
						fi

						gec.localgroupname="${user}@${domain}"
						gec.nfsownergroup="${user}@${idmap_config.nfsdomain}"
						(( gec.localgid=pgec.gid ))
						(( gec.nfsgid=pgec.gid ))
						print -v gec
						return 0
					else
						print -u2 -f "cygwin_idmapper.ksh(cfg=%q): getent group %q returned garbage %q.\n" \
							"${c.idmapconfigname-}" \
							"${c.name}" "${gec.localgid-}"
						return 1
					fi
				fi
			fi

			print -u2 -f "cygwin_idmapper.ksh(cfg=%q): Group %q not found.\n" "${c.idmapconfigname-}" "${c.name}"
			return 1
			;;
		'lookup_user_by_nfsserver_owner')
			#
			# Try static info
			#

			# Numeric ? Try looking up static UID
			if [[ "${c.name}" == ~(Elr)[[:digit:]]+ ]] ; then
				# Numeric ? Try looking up static UID
				for s in "${!c.localusers[@]}" ; do
					if (( c.localusers["$s"].nfsuid == c.name )) ; then
						print -v c.localusers["$s"]
						return 0
					fi
				done
				# getent passwd accepts numeric uids too, so continue below
			else
				# Search for user name
				for s in "${!c.localusers[@]}" ; do
					if [[ "${c.localusers["$s"].nfsowner}" == "${c.name}" ]] ; then
						print -v c.localusers["$s"]
						return 0
					fi
				done
			fi

			#
			# try getent passwd
			#
			compound pgec # parsed getent data compound var
			compound gec # getent compound var
			stdout="${ getent_nfs_domain_passwd "${c.name}" ;}"
			if (( $? == 0 )) && [[ "${stdout}" != '' ]] ; then
				parse_getent_passwd2compound pgec "${stdout}"
				if (( $? == 0 )) ; then
					if [[ "${pgec.uid-}" == ~(Elr)[[:digit:]]+ ]] ; then
						compound nt_parsed
						parse_ntaccount nt_parsed "${pgec.comment}"
						gec.localaccountname="${nt_parsed.user}@${nt_parsed.domain}"
						gec.nfsowner="${nt_parsed.user}@${idmap_config.nfsdomain}"
						(( gec.localuid=pgec.uid ))
						(( gec.nfsuid=pgec.uid ))
						print -v gec
						return 0
					else
						print -u2 -f "cygwin_idmapper.ksh(cfg=%q): getent passwd %q returned garbage %q.\n" \
							"${c.idmapconfigname-}" \
							"${c.name}" "${gec.localuid-}"
						return 1
					fi
				fi
			fi

			print -u2 -f "cygwin_idmapper.ksh(cfg=%q): Account %q not found.\n" "${c.idmapconfigname-}" "${c.name}"
			return 1
			;;
		'lookup_group_by_nfsserver_owner_group')
			#
			# Try static info
			#
			if [[ "${c.name}" == ~(Elr)[[:digit:]]+ ]] ; then
				# Numeric ? Try looking up static UID
				for s in "${!c.localgroups[@]}" ; do
					if (( c.localgroups["$s"].localgid == c.name )) ; then
						print -v c.localgroups["$s"]
						return 0
					fi
				done
				# getent group accepts numeric gids too, so continue below
			else
				# Search for group name
				for s in "${!c.localgroups[@]}" ; do
					if [[ "${c.localgroups["$s"].nfsownergroup}" == "${c.name}" ]] ; then
						print -v c.localgroups["$s"]
						return 0
					fi
				done
			fi

			#
			# try getent group
			#
			compound pgec # parsed getent data compound var
			compound gec # getent compound var
			stdout="${ getent_nfs_domain_group "${c.name}" ;}"
			if (( $? == 0 )) && [[ "${stdout}" != '' ]] ; then
				parse_getent_group2compound pgec "${stdout}"
				if (( $? == 0 )) ; then
					if [[ "${pgec.gid-}" == ~(Elr)[[:digit:]]+ ]] ; then
						if [[ "${pgec.group_name}" == *"+"* ]]; then
							domain="${pgec.group_name%%+*}"
							user="${input#*+}"
						else
							# No '+' found, fallback to the local machine name
							domain="${COMPUTERNAME}"
							user="${pgec.group_name}"
						fi

						gec.localgroupname="${user}@${domain}"
						gec.nfsownergroup="${user}@${idmap_config.nfsdomain}"
						(( gec.localgid=pgec.gid ))
						(( gec.nfsgid=pgec.gid ))
						print -v gec
						return 0
					else
						print -u2 -f "cygwin_idmapper.ksh(cfg=%q): getent group %q returned garbage %q.\n" \
							"${c.idmapconfigname-}" \
							"${c.name}" "${gec.localgid-}"
						return 1
					fi
				fi
			fi

			print -u2 -f "cygwin_idmapper.ksh(cfg=%q): Group %q not found.\n" "${c.idmapconfigname-}" "${c.name}"
			return 1
			;;
		*)
			print -u2 -f "cygwin_idmapper.ksh: Unknown mode %q.\n" "${c.mode-}"
			return 1
			;;
	esac

	# notreached
	return 1
}


#
# main
#
set -o nounset

export PATH='/bin:/usr/bin'
export LC_ALL='en_US.UTF-8'

#
# idmapper script config data
#
case "$1" in
	# default config
	*)
		compound idmap_config=(
			#typeset -r localdomain='GLOBAL.LOC'	# Default domain for Windows
			#typeset -r nfsdomain='global.loc'	# Default domain for NFS server
			typeset -r localdomain="$( < '/proc/registry/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/Tcpip/Parameters/Domain' )"
			typeset -r nfsdomain="$( tr '[:upper:]' '[:lower:]' <'/proc/registry/HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/Tcpip/Parameters/Domain' )"

			# Define NFS server type
			# * Values can be "windows/en", "windows/de", "windows/fr", "freebsd", "solaris", "linux"
			# * This is neccesary because
			# - Windows localises account names on both client and server side
			# (e.g. German Windows machine connecting to a French WindowsServer 2022)
			# - Different NFS servers might use different names for the same group
			# (e.g. SAMBA vs. kernel CIFS server)
			typeset -r servertype='linux'
		)
		;;
esac

main_dispatch "$@"
exit $?
# EOF.
