#!/bin/ksh93

set -o nounset
typeset IFS=''

#
# global variables for this script
# (stored in compound variable so we
# can do a $ print -u2 -v c # for debugging)
#
compound c=(
	mode="$1"
	name="$2"
)

compound -A localusers=(
	["roland_mainz"]=(
		localaccoutname='roland_mainz'
		localuid=197608
		localgid=197121
	)
	["siegfried_wulsch"]=(
		localaccoutname='siegfried_wulsch'
		localuid=197609
		localgid=197121
	)
	["SYSTEM"]=(
		localaccoutname='SYSTEM'
		localuid=18
		localgid=18
	)
	["rmainz"]=(
		localaccoutname='rmainz'
		localuid=1616
		localgid=1616
	)
	["swulsch"]=(
		localaccoutname='swulsch'
		localuid=1818
		localgid=1818
	)
	["root"]=(
		localaccoutname='root'
		localuid=0
		localgid=0
	)
	["nobody"]=(
		localaccoutname='nobody'
		localuid=65534
		localgid=65534
	)
)

compound -A localgroups=(
	["Kein"]=(
		localgroupname='Kein'
		localgid=197121
	)
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
		print -u2 "cygwin_idmapper.ksh: Unknown mode %q." "${c.mode}"
		exit 1
		;;
esac

# EOF.
