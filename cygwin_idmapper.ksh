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
compound c=(
	mode="$1"
	name="${2-}"
)

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

# User "SYSTEM": de_DE: "SYSTEM" ...
stdout="$(getent passwd 'S-1-5-18')"
c.localised_usernames['SYSTEM']="${stdout%%:*}"

# User "Adminstrator": fr_FR: "Administrateur" ...
stdout="$(getent passwd 'S-1-5-21-3286904461-661230000-4220857270-500')"
c.localised_usernames['Administrator']="${stdout%%:*}"

# Group "None": de_DE: "Kein", fr_FR: "Aucun" ...
stdout="$(getent group 'S-1-5-21-3286904461-661230000-4220857270-513')"
c.localised_groupnames['None']="${stdout%%:*}"

compound -A localusers=(
	#
	# System accounts
	#
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

compound -A localgroups=(
	#
	# System accounts
	#
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
)

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
		getent passwd "${c.name}" | \
			IFS=':' read gec.localaccountname dummy1 gec.localuid gec.localgid dummy2

		if [[ "${gec.localaccountname-}" != '' ]] ; then
			if [[ "${gec.localuid-}" == ~(Elr)[[:digit:]]+ && "${gec.localgid-}" == ~(Elr)[[:digit:]]+ ]] ; then
				print -v gec
				exit 0
			else
				print -u2 -f "cygwin_idmapper.ksh: getent passwd %q returned garbage.\n" "${c.name}"
			fi
		fi

		print -u2 -f "cygwin_idmapper.ksh: Account '%q' not found.\n" "${c.name}"
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
		getent group "${c.name}" | \
			IFS=':' read gec.localgroupname dummy1 gec.localgid dummy2

		if [[ "${gec.localgroupname-}" != '' ]] ; then
			if [[ "${gec.localgid-}" == ~(Elr)[[:digit:]]+ ]] ; then
				print -v gec
				exit 0
			else
				print -u2 -f "cygwin_idmapper.ksh: getent group %q returned garbage.\n" "${c.name}"
			fi
		fi

		print -u2 -f "cygwin_idmapper.ksh: Group '%q' not found.\n" "${c.name}"
		exit 1
		;;
	*)
		print -u2 -f "cygwin_idmapper.ksh: Unknown mode %q.\n" "${c.mode}"
		exit 1
		;;
esac

# EOF.
