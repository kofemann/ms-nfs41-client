#!/bin/ksh93

set -o nounset
typeset IFS=''

export PATH='/bin:/usr/bin'

export LC_ALL='en_US.UTF-8'

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
	c.localised_usernames['SYSTEM']="${stdout%%:*}"
fi

# User "Adminstrator": fr_FR: "Administrateur" ...
stdout="$(getent passwd "${machine_sid}-500")"
if (( $? == 0 )) && [[ "$stdout" != ~(El)Unknown\+User: ]] ; then
	c.localised_usernames['Administrator']="${stdout%%:*}"

fi

# Group "None": de_DE: "Kein", fr_FR: "Aucun" ...
stdout="$(getent group "${machine_sid}-513")"
if (( $? == 0 )) && [[ "$stdout" != ~(El)Unknown\+Group: ]] ; then
	c.localised_groupnames['None']="${stdout%%:*}"
fi

# Group "Administrators" de_DE: "Administratoren"
# (primarily used by WindowsServer (2019) NFSv4.1 server)
stdout="$(getent group 'S-1-5-32-544')"
if (( $? == 0 )) && [[ "$stdout" != ~(El)Unknown\+Group: ]] ; then
	c.localised_groupnames['Administrators']="${stdout%%:*}"
fi

# Group "Users" de_DE: "Benutzer", fr_FR: "Utilisateurs"
# (primarily used by WindowsServer (2019) NFSv4.1 server)
stdout="$(getent group 'S-1-5-32-545')"
if (( $? == 0 )) && [[ "$stdout" != ~(El)Unknown\+Group: ]] ; then
	c.localised_groupnames['Users']="${stdout%%:*}"
fi

compound -A localusers=(
	#
	# System accounts
	#

	#
	# Site-specific users
	#
	["roland_mainz"]=(
		localaccountname='roland_mainz'
		localuid=197608
		localgid=197121
	)
	["siegfried_wulsch"]=(
		localaccountname='siegfried_wulsch'
		localuid=197609
		localgid=197121
	)
	["rmainz"]=(
		localaccountname='rmainz'
		localuid=1616
		localgid=1616
	)
	["swulsch"]=(
		localaccountname='swulsch'
		localuid=1818
		localgid=1818
	)
	["root"]=(
		localaccountname='root'
		localuid=0
		localgid=0
	)
	["nobody"]=(
		localaccountname='nobody'
		localuid=65534
		localgid=65534
	)
)

if [[ -v c.localised_usernames['Administrator'] ]] ; then
	localusers+=(
		["${c.localised_usernames['Administrator']}"]=(
			localaccountname="${c.localised_usernames['Administrator']}"
			localuid=197108
			localgid=197121
		)
		['Administrator']=(
			localaccountname="${c.localised_usernames['Administrator']}"
			localuid=197108
			localgid=197121
		)
		# French user "Administrator"
		['Administrateur']=(
			localaccountname="${c.localised_usernames['Administrator']}"
			localuid=197108
			localgid=197121
		)
	)
fi
if [[ -v c.localised_usernames['SYSTEM'] ]] ; then
	localusers+=(
		["${c.localised_usernames['SYSTEM']}"]=(
			localaccountname="${c.localised_usernames['SYSTEM']}"
			localuid=18
			localgid=18
		)
		["SYSTEM"]=(
			localaccountname="${c.localised_usernames['SYSTEM']}"
			localuid=18
			localgid=18
		)
		# French user "SYSTEM"
		# FIXME: This should be $'Syst\u[e8]me', but ksh93 1.0.10
		# doesn't work
		[$'Syst\xc3\xa8me']=(
			localaccountname="${c.localised_usernames['SYSTEM']}"
			localuid=18
			localgid=18
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
		localgroupname='rmainz'
		localgid=1616
	)
	["swulsch"]=(
		localgroupname='swulsch'
		localgid=1818
	)
	["root"]=(
		localgroupname='root'
		localgid=0
	)
	["nogroup"]=(
		localgroupname='nogroup'
		localgid=65534
	)
	#
	# Group "sys" required for Solaris/Illumos nfsd
	#
	["sys"]=(
		localgroupname='sys'
		localgid=3
	)
	#
	# Group "nobody" required for Solaris/Illumos nfsd
	# Question is why "nobody" shows up in a "group" idmapperr lookup
	#
	["nobody"]=(
		localgroupname='nobody'
		localgid=65534
	)
)

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

if [[ -v c.localised_groupnames['None'] ]] ; then
	localgroups+=(
		["${c.localised_groupnames['None']}"]=(
			localgroupname="${c.localised_groupnames['None']}"
			localgid=197121
		)
		["None"]=(
			localgroupname="${c.localised_groupnames['None']}"
			localgid=197121
		)
		# French Windows localised group name for "None"
		['Aucun']=(
			localgroupname="${c.localised_groupnames['None']}"
			localgid=197121
		)
		# German Windows localised group name for "None"
		["Kein"]=(
			localgroupname="${c.localised_groupnames['None']}"
			localgid=197121
		)
	)
fi

if [[ -v c.localised_groupnames['Administrators'] ]] ; then
	localgroups+=(
		["${c.localised_groupnames['Administrators']}"]=(
			localgroupname="${c.localised_groupnames['Administrators']}"
			localgid=544
		)
		['Administrators']=(
			localgroupname="${c.localised_groupnames['Administrators']}"
			localgid=544
		)
		# French Windows localised group name for "Administrators"
		# (from https://learn.microsoft.com/fr-fr/windows-server/identity/ad-ds/manage/understand-security-identifiers)
		['Administrateurs']=(
			localgroupname="${c.localised_groupnames['Administrators']}"
			localgid=544
		)
		# German Windows localised group name for "Administrators"
		['Administratoren']=(
			localgroupname="${c.localised_groupnames['Administrators']}"
			localgid=544
		)
	)
fi

if [[ -v c.localised_groupnames['Users'] ]] ; then
	localgroups+=(
		["${c.localised_groupnames['Users']}"]=(
			localgroupname="${c.localised_groupnames['Users']}"
			localgid=545
		)
		['Users']=(
			localgroupname="${c.localised_groupnames['Users']}"
			localgid=545
		)
		# French Windows localised group name for "Users"
		# (from https://learn.microsoft.com/fr-fr/windows-server/identity/ad-ds/manage/understand-security-identifiers)
		['Utilisateurs']=(
			localgroupname="${c.localised_groupnames['Users']}"
			localgid=545
		)
		# German Windows localised group name for "Users"
		['Benutzer']=(
			localgroupname="${c.localised_groupnames['Users']}"
			localgid=545
		)
	)
fi

case "${c.mode}" in
	'nfsserver_owner2localaccount')
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
		fi

		if [[ -v localusers["${c.name}"] ]] ; then
			print -v localusers["${c.name}"]
			exit 0
		fi

		#
		# try getent passwd
		#
		compound gec # getent compound var
		typeset dummy1 dummy2
		getent_local_domain_passwd "${c.name}" | \
			IFS=':' read gec.localaccountname dummy1 gec.localuid gec.localgid dummy2

		if [[ "${gec.localaccountname-}" != '' ]] ; then
			if [[ "${gec.localuid-}" == ~(Elr)[[:digit:]]+ && "${gec.localgid-}" == ~(Elr)[[:digit:]]+ ]] ; then
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
			for s in "${!localgroups[@]}" ; do
				if (( localgroups[$s].localgid == c.name )) ; then
					print -v localgroups[$s]
					exit 0
				fi
			done
			# getent group accepts numeric gids too, so continue below
		fi

		if [[ -v localgroups["${c.name}"] ]] ; then
			print -v localgroups["${c.name}"]
			exit 0
		fi

		#
		# try getent group
		#
		compound gec # getent compound var
		typeset dummy1 dummy2
		getent_local_domain_group "${c.name}" | \
			IFS=':' read gec.localgroupname dummy1 gec.localgid dummy2

		if [[ "${gec.localgroupname-}" != '' ]] ; then
			if [[ "${gec.localgid-}" == ~(Elr)[[:digit:]]+ ]] ; then
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
