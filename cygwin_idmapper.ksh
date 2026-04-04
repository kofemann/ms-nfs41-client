#!/bin/ksh93

set -o nounset
typeset IFS=''

export PATH='/bin:/usr/bin'

export LC_ALL='en_US.UTF-8'

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

#
# global variables for this script
# (stored in compound variable so we
# can do a $ print -u2 -v c # for debugging)
#
compound c

c.mode="$1"
if (( $# > 1 )) ; then
	# strip '"' characters (for Cygwin 3.3 compatibility)
	# note that "${2-//..." does NOT work!
	c.name="${2//\"/}"
fi

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
# FIXME: This still means we send a localised group name
# to the NFSv4 server, and it needs /etc/group entries for all
# localised variations of group "None". In the future the idmapper
# should do the mapping in both directions to avoid this.
#
typeset stdout

typeset -A c.localised_usernames
typeset -A c.localised_groupnames

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

# User "SYSTEM": de_DE: "SYSTEM" ...
stdout="$(getent passwd 'S-1-5-18')"
if (( $? == 0 )) && [[ "$stdout" != ~(El)Unknown\+User: ]] ; then
	compound nt_parse
	parse_ntaccount nt_parse "$(sed -E 's/.+U-([^,]+).+/\1/' <<<"$stdout")"
	c.localised_usernames['SYSTEM']="${nt_parse.user}@${nt_parse.domain}"
fi

# User "Adminstrator": fr_FR: "Administrateur" ...
stdout="$(getent passwd "${machine_sid}-500")"
if (( $? == 0 )) && [[ "$stdout" != ~(El)Unknown\+User: ]] ; then
	compound nt_parse
	parse_ntaccount nt_parse "$(sed -E 's/.+U-([^,]+).+/\1/' <<<"$stdout")"
	c.localised_usernames['Administrator']="${nt_parse.user}@${nt_parse.domain}"
fi

# Group "SYSTEM": de_DE: "SYSTEM" ...
# (we use getent passwd here because getent group does not give us a domain name)
stdout="$(getent passwd 'S-1-5-18')"
if (( $? == 0 )) && [[ "$stdout" != ~(El)Unknown\+User: ]] ; then
	compound nt_parse
	parse_ntaccount nt_parse "$(sed -E 's/.+U-([^,]+).+/\1/' <<<"$stdout")"
	c.localised_groupnames['SYSTEM']="${nt_parse.user}@${nt_parse.domain}"
fi

# Group "None": de_DE: "Kein", fr_FR: "Aucun" ...
# (we use getent passwd here because getent group does not give us a domain name)
stdout="$(getent passwd "${machine_sid}-513")"
if (( $? == 0 )) && [[ "$stdout" != ~(El)Unknown\+Group: ]] ; then
	compound nt_parse
	parse_ntaccount nt_parse "$(sed -E 's/.+U-([^,]+).+/\1/' <<<"$stdout")"
	c.localised_groupnames['None']="${nt_parse.user}@${nt_parse.domain}"
fi

# Group "Administrators" de_DE: "Administratoren"
# (primarily used by WindowsServer (2019) NFSv4.1 server)
# (we use getent passwd here because getent group does not give us a domain name)
stdout="$(getent passwd 'S-1-5-32-544')"
if (( $? == 0 )) && [[ "$stdout" != ~(El)Unknown\+Group: ]] ; then
	compound nt_parse
	parse_ntaccount nt_parse "$(sed -E 's/.+U-([^,]+).+/\1/' <<<"$stdout")"
	c.localised_groupnames['Administrators']="${nt_parse.user}@${nt_parse.domain}"
fi

# Group "Users" de_DE: "Benutzer", fr_FR: "Utilisateurs"
# (primarily used by WindowsServer (2019) NFSv4.1 server)
# (we use getent passwd here because getent group does not give us a domain name)
stdout="$(getent passwd 'S-1-5-32-545')"
if (( $? == 0 )) && [[ "$stdout" != ~(El)Unknown\+Group: ]] ; then
	compound nt_parse
	parse_ntaccount nt_parse "$(sed -E 's/.+U-([^,]+).+/\1/' <<<"$stdout")"
	c.localised_groupnames['Users']="${nt_parse.user}@${nt_parse.domain}"
fi

if [[ ! -v COMPUTERNAME ]] ; then
	printf -u2 -f $"ERROR: COMPUTERNAME var not set\n"
	export COMPUTERNAME="$(uname -n | tr '[:lower:]' '[:upper:]')"
	exit 1
fi

compound idmap_config=(
	typeset -r localdomain='GLOBAL.LOC'	# Default domain for Windows
	typeset -r nfsdomain='global.loc'	# Default domain for NFS server
)

compound -A localusers=(
	#
	# System accounts
	#

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
	#["rmainz"]=(
	#	localaccountname="rmainz@${COMPUTERNAME}"
	#	localuid=1616
	#	nfsowner="rmainz@${idmap_config.nfsdomain}"
	#	nfsuid=1616
	#)
	#["swulsch"]=(
	#	localaccountname="swulsch@${COMPUTERNAME}"
	#	localuid=1818
	#	nfsowner="swulsch@${idmap_config.nfsdomain}"
	#	nfsuid=1818
	#)
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

if [[ -v c.localised_usernames['Administrator'] ]] ; then
	localusers+=(
		["${c.localised_usernames['Administrator']}"]=(
			localaccountname="${c.localised_usernames['Administrator']}"
			localuid=197108
			nfsuid=197108
			nfsowner="Administrator@${idmap_config.nfsdomain}"
		)
		['Administrator']=(
			localaccountname="${c.localised_usernames['Administrator']}"
			localuid=197108
			nfsowner="Administrator@${idmap_config.nfsdomain}"
			nfsuid=197108
		)
		# French user "Administrator"
		['Administrateur']=(
			localaccountname="${c.localised_usernames['Administrator']}"
			localuid=197108
			nfsowner="Administrator@${idmap_config.nfsdomain}"
			nfsuid=197108
		)
	)
fi
if [[ -v c.localised_usernames['SYSTEM'] ]] ; then
	localusers+=(
		["${c.localised_usernames['SYSTEM']}"]=(
			localaccountname="${c.localised_usernames['SYSTEM']}"
			localuid=18
			nfsowner="SYSTEM@${idmap_config.nfsdomain}"
			nfsuid=18
		)
		["SYSTEM"]=(
			localaccountname="${c.localised_usernames['SYSTEM']}"
			localuid=18
			nfsowner="SYSTEM@${idmap_config.nfsdomain}"
			nfsuid=18
		)
		# French user "SYSTEM"
		# FIXME: This should be $'Syst\u[e8]me', but ksh93 1.0.10
		# doesn't work
		[$'Syst\xc3\xa8me']=(
			localaccountname="${c.localised_usernames['SYSTEM']}"
			localuid=18
			nfsowner="SYSTEM@${idmap_config.nfsdomain}"
			nfsuid=18
		)
	)
fi

compound -A localgroups=(
	#
	# System accounts
	#


	#
	# Site-specific users
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
	# Question is why "nobody" shows up in a "group" idmapperr lookup
	#
	["nobody"]=(
		localgroupname="nobody@${COMPUTERNAME}"
		localgid=65534
		nfsownergroup="nobody@${idmap_config.nfsdomain}"
		nfsgid=65534
	)
)

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

if [[ -v c.localised_groupnames['SYSTEM'] ]] ; then
	localgroups+=(
		["${c.localised_groupnames['SYSTEM']}"]=(
			localgroupname="${c.localised_usernames['SYSTEM']}"
			localgid=18
			nfsownergroup="SYSTEM@${idmap_config.nfsdomain}"
			nfsgid=18
		)
		["SYSTEM"]=(
			localgroupname="${c.localised_usernames['SYSTEM']}"
			localgid=18
			nfsownergroup="SYSTEM@${idmap_config.nfsdomain}"
			nfsgid=18
		)
		# French user "SYSTEM"
		# FIXME: This should be $'Syst\u[e8]me', but ksh93 1.0.10
		# doesn't work
		[$'Syst\xc3\xa8me']=(
			localgroupname="${c.localised_usernames['SYSTEM']}"
			localgid=18
			nfsownergroup="SYSTEM@${idmap_config.nfsdomain}"
			nfsgid=18
		)
	)
fi

if [[ -v c.localised_groupnames['None'] ]] ; then
	localgroups+=(
		["${c.localised_groupnames['None']}"]=(
			localgroupname="${c.localised_groupnames['None']}"
			localgid=197121
			nfsownergroup="None@${idmap_config.nfsdomain}"
			nfsgid=197121
		)
		["None"]=(
			localgroupname="${c.localised_groupnames['None']}"
			localgid=197121
			nfsownergroup="None@${idmap_config.nfsdomain}"
			nfsgid=197121
		)
		# French Windows localised group name for "None"
		['Aucun']=(
			localgroupname="${c.localised_groupnames['None']}"
			localgid=197121
			nfsownergroup="None@${idmap_config.nfsdomain}"
			nfsgid=197121
		)
		# German Windows localised group name for "None"
		["Kein"]=(
			localgroupname="${c.localised_groupnames['None']}"
			localgid=197121
			nfsownergroup="None@${idmap_config.nfsdomain}"
			nfsgid=197121
		)
	)
fi

if [[ -v c.localised_groupnames['Administrators'] ]] ; then
	localgroups+=(
		["${c.localised_groupnames['Administrators']}"]=(
			localgroupname="${c.localised_groupnames['Administrators']}"
			localgid=544
			nfsownergroup="Administrators@${idmap_config.nfsdomain}"
			nfsgid=544
		)
		['Administrators']=(
			localgroupname="${c.localised_groupnames['Administrators']}"
			localgid=544
			nfsownergroup="Administrators@${idmap_config.nfsdomain}"
			nfsgid=544
		)
		# French Windows localised group name for "Administrators"
		# (from https://learn.microsoft.com/fr-fr/windows-server/identity/ad-ds/manage/understand-security-identifiers)
		['Administrateurs']=(
			localgroupname="${c.localised_groupnames['Administrators']}"
			localgid=544
			nfsownergroup="Administrators@${idmap_config.nfsdomain}"
			nfsgid=544
		)
		# German Windows localised group name for "Administrators"
		['Administratoren']=(
			localgroupname="${c.localised_groupnames['Administrators']}"
			localgid=544
			nfsownergroup="Administrators@${idmap_config.nfsdomain}"
			nfsgid=544
		)
	)
fi

if [[ -v c.localised_groupnames['Users'] ]] ; then
	localgroups+=(
		["${c.localised_groupnames['Users']}"]=(
			localgroupname="${c.localised_groupnames['Users']}"
			localgid=545
			nfsownergroup="Users@${idmap_config.nfsdomain}"
			nfsgid=545
		)
		['Users']=(
			localgroupname="${c.localised_groupnames['Users']}"
			localgid=545
			nfsownergroup="Users@${idmap_config.nfsdomain}"
			nfsgid=545
		)
		# French Windows localised group name for "Users"
		# (from https://learn.microsoft.com/fr-fr/windows-server/identity/ad-ds/manage/understand-security-identifiers)
		['Utilisateurs']=(
			localgroupname="${c.localised_groupnames['Users']}"
			localgid=545
			nfsownergroup="Users@${idmap_config.nfsdomain}"
			nfsgid=545
		)
		# German Windows localised group name for "Users"
		['Benutzer']=(
			localgroupname="${c.localised_groupnames['Users']}"
			localgid=545
			nfsownergroup="Users@${idmap_config.nfsdomain}"
			nfsgid=545
		)
	)
fi

#
# main dispatcher
#
case "${c.mode}" in
	'localname2localaccount')
		#
		# Try static info
		#
		if [[ "${c.name}" == ~(Elr)[[:digit:]]+ ]] ; then
			for s in "${!localusers[@]}" ; do
				if (( localusers[$s].localuid == c.name )) ; then
					print -v localusers[$s]
					exit 0
				fi
			done
			# getent passwd accepts numeric uids too, so continue below
		else
			#if [[ -v localusers["${c.name}"] ]] ; then
			#	print -v localusers["${c.name}"]
			#	exit 0
			#fi
			for s in "${!localusers[@]}" ; do
				if [[ "${localusers[$s].localaccountname}" == "${c.name}" ]] ; then
					print -v localusers[$s]
					exit 0
				fi
			done
		fi

		#
		# try getent passwd
		#
		compound gec # getent compound var
		typeset dummy1 dummy2 s
		getent_local_domain_passwd "${c.name}" | \
			IFS=':' read -r dummy1 dummy2 gec.localuid dummy3 s dummy4

		if [[ "${s-}" != '' ]] ; then
			if [[ "${gec.localuid-}" == ~(Elr)[[:digit:]]+ ]] ; then
				compound nt_parsed
				parse_ntaccount nt_parsed "$s"
				gec.localaccountname="${nt_parsed.user}@${nt_parsed.domain}"
				gec.nfsowner="${nt_parsed.user}@${idmap_config.nfsdomain}"
				(( gec.nfsuid=gec.localuid ))
				print -v gec
				exit 0
			else
				print -u2 -f "cygwin_idmapper.ksh: getent passwd %q returned garbage.\n" "${c.name}"
			fi
		fi

		print -u2 -f "cygwin_idmapper.ksh: Account %q not found.\n" "${c.name}"
		exit 1
		;;
	'localgroup2localgroup')
		#
		# Try static info
		#
		if [[ "${c.name}" == ~(Elr)[[:digit:]]+ ]] ; then
			for s in "${!localgroups[@]}" ; do
				if (( localgroups[$s].localgid == c.name )) ; then
					print -v localgroups[$s]
					exit 0
				fi
			done
			# getent group accepts numeric gids too, so continue below
		else
			#if [[ -v localgroups["${c.name}"] ]] ; then
			#	print -v localgroups["${c.name}"]
			#	exit 0
			#fi
			for s in "${!localgroups[@]}" ; do
				if [[ "${localgroups[$s].localgroupname}" == "${c.name}" ]] ; then
					print -v localgroups[$s]
					exit 0
				fi
			done
		fi

		#
		# try getent group
		#
		compound gec # getent compound var
		typeset dummy1 dummy2 s
		getent_local_domain_group "${c.name}" | \
			IFS=':' read s dummy1 gec.localgid dummy2

		if [[ "${s-}" != '' ]] ; then
			if [[ "${gec.localgid-}" == ~(Elr)[[:digit:]]+ ]] ; then
				if [[ "$s" == *"+"* ]]; then
					domain="${s%%+*}"
					user="${input#*+}"
				else
					# No '+' found, fallback to the local machine name
					domain="${COMPUTERNAME}"
					user="$s"
				fi

				gec.localgroupname="${user}@${domain}"
				gec.nfsownergroup="${user}@${idmap_config.nfsdomain}"
				(( gec.nfsgid=gec.localgid ))
				print -v gec
				exit 0
			else
				print -u2 -f "cygwin_idmapper.ksh: getent group %q returned garbage.\n" "${c.name}"
			fi
		fi

		print -u2 -f "cygwin_idmapper.ksh: Group %q not found.\n" "${c.name}"
		exit 1
		;;
	'nfsserver_owner2localaccount')
		#
		# Try static info
		#

		# Numeric ? Try looking up static UID
		if [[ "${c.name}" == ~(Elr)[[:digit:]]+ ]] ; then
			# Numeric ? Try looking up static UID
			for s in "${!localusers[@]}" ; do
				if (( localusers[$s].nfsuid == c.name )) ; then
					print -v localusers[$s]
					exit 0
				fi
			done
			# getent passwd accepts numeric uids too, so continue below
		else
			# Search for user name
			for s in "${!localusers[@]}" ; do
				if [[ "${localusers[$s].nfsowner}" == "${c.name}" ]] ; then
					print -v localusers[$s]
					exit 0
				fi
			done
		fi

		#
		# try getent passwd
		#
		compound gec # getent compound var
		typeset dummy1 dummy2 s
		getent_nfs_domain_passwd "${c.name}" | \
			IFS=':' read -r dummy1 dummy2 gec.localuid dummy3 s dummy4

		if [[ "${s-}" != '' ]] ; then
			if [[ "${gec.localuid-}" == ~(Elr)[[:digit:]]+ ]] ; then
				compound nt_parsed
				parse_ntaccount nt_parsed "$s"
				gec.localaccountname="${nt_parsed.user}@${nt_parsed.domain}"
				gec.nfsowner="${nt_parsed.user}@${idmap_config.nfsdomain}"
				(( gec.nfsuid=gec.localuid ))
				print -v gec
				exit 0
			else
				print -u2 -f "cygwin_idmapper.ksh: getent passwd %q returned garbage.\n" "${c.name}"
			fi
		fi

		print -u2 -f "cygwin_idmapper.ksh: Account %q not found.\n" "${c.name}"
		exit 1
		;;
	'nfsserver_owner_group2localgroup')
		#
		# Try static info
		#
		if [[ "${c.name}" == ~(Elr)[[:digit:]]+ ]] ; then
			# Numeric ? Try looking up static UID
			for s in "${!localgroups[@]}" ; do
				if (( localgroups[$s].localgid == c.name )) ; then
					print -v localgroups[$s]
					exit 0
				fi
			done
			# getent group accepts numeric gids too, so continue below
		else
			# Search for user name
			for s in "${!localgroups[@]}" ; do
				if [[ "${localgroups[$s].nfsownergroup}" == "${c.name}" ]] ; then
					print -v localgroups[$s]
					exit 0
				fi
			done
		fi

		#
		# try getent group
		#
		compound gec # getent compound var
		typeset dummy1 dummy2 s
		getent_nfs_domain_group "${c.name}" | \
			IFS=':' read s dummy1 gec.localgid dummy2

		if [[ "${s-}" != '' ]] ; then
			if [[ "${gec.localgid-}" == ~(Elr)[[:digit:]]+ ]] ; then
				if [[ "$s" == *"+"* ]]; then
					domain="${s%%+*}"
					user="${input#*+}"
				else
					# No '+' found, fallback to the local machine name
					domain="${COMPUTERNAME}"
					user="$s"
				fi

				gec.localgroupname="${user}@${domain}"
				gec.nfsownergroup="${user}@${idmap_config.nfsdomain}"
				(( gec.nfsgid=gec.localgid ))
				print -v gec
				exit 0
			else
				print -u2 -f "cygwin_idmapper.ksh: getent group %q returned garbage.\n" "${c.name}"
			fi
		fi

		print -u2 -f "cygwin_idmapper.ksh: Group %q not found.\n" "${c.name}"
		exit 1
		;;
	*)
		print -u2 -f "cygwin_idmapper.ksh: Unknown mode %q.\n" "${c.mode}"
		exit 1
		;;
esac

# EOF.
