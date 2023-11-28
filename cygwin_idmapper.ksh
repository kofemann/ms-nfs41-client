#!/bin/ksh93

set -o nounset
typeset IFS=''

#
# global variables
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
		localaccoutname='Kein'
		localgid=197121
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
	["nogroup"]=(
		localaccoutname='nogroup'
		localuid=65534
		localgid=65534
	)
)

case "${c.mode}" in
	'nfsserver_owner2localaccount')
		if [[ "${c.name}" == ~(Elr)[[:digit:]]+ ]] ; then
			for s in "${!localusers[@]}" ; do
				if (( localusers[$s].localuid == c.name )) ; then
					print -v localusers[$s]
					exit 0
				fi
			done
		fi

		if [[ -v localusers["${c.name}"] ]] ; then
			print -v localusers["${c.name}"]
			exit 0
		else
			print -u2 -f "cygwin_idmapper.ksh: Account '%s' not found.\n" "${c.name}"
			exit 1
		fi
		;;
	'nfsserver_owner_group2localgroup')
		if [[ "${c.name}" == ~(Elr)[[:digit:]]+ ]] ; then
			for s in "${!localgroups[@]}" ; do
				if (( localgroups[$s].localgid == c.name )) ; then
					print -v localgroups[$s]
					exit 0
				fi
			done
		fi

		if [[ -v localgroups["${c.name}"] ]] ; then
			print -v localgroups["${c.name}"]
			exit 0
		else
			print -u2 -f "cygwin_idmapper.ksh: Account '%s' not found.\n" "${c.name}"
			exit 1
		fi
		;;
	*)
		print -u2 "cygwin_idmapper.ksh: Unknown mode"
		exit 1
		;;
esac

# EOF.
