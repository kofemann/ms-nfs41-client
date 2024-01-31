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
# nfsurlconv.ksh - convert host/port/path from/to a nfs://-URL

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
		(?:\/(.*?))?/X}"		# path (optional)

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

	if [[ -v data.uripath ]] ; then
		data.path="${ printf "${data.uripath//~(E)(?:%([[:xdigit:]][[:xdigit:]]))/\\x\1}" ; }"
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


function urlencodestr
{
	set -o nounset

	nameref out_encodedstr=$1
	typeset in_str="$2"
	typeset ch ch_hexval dummy
	integer ch_num
	typeset url=''

	#
	# URLs encode non-ASCII characters as UTF-8 on byte-level,
	# while POSIX shells (ksh93, bash, etc.) operate on
	# characters (which *MAY* be - like UTF-8 - encoded as
	# multibyte characters, but may use a different encoding
	# like ISO8859-1 or GB18030).
	# The code below solves that by using iconv(1) to
	# convert everything into UTF-8 bytes, then convert the
	# bytes via od(1) into pairs of { position, hexadecimal
	# character value ("hexval") }, and then turn these to
	# ASCII ("ch") / numeric ASCII ("ch_num") values
	# (this assumes that the current LC_CTYPE is
	# ASCII-compatible)
	#
	printf '%s' "$in_str" | \
		iconv -t 'UTF-8' | \
		od -t x1 -w1 -v | \
		while read dummy ch_hexval ; do
		[[ "$ch_hexval" != '' ]] || break

		ch_num="${ printf "%d" "0x$ch_hexval" ; }"
		if (( ch_num <= 127 )) ; then
			typeset ch="${ printf "\x$ch_hexval" ; }"
		else
			#
			# character is outside ASCII, shell may
			# not be able to represent this
			#
			[[ -v ch ]] && unset ch
		fi

		#
		# From RFC 1738 ("Uniform Resource Locators (URL)"):
		# unsafe characters in URLS:
		# "{", "}", "|", "\", "^", "~", "[", "]", and "`"
		# characters which must always be encoded:
		# "#", "%"
		# characters which must be encoded because they have a special meaning:
		# ";", "/", "?", ":", "@", "=" and "&"
		# Only alphanumerics, "$-_.+!*'()," and reserved characters
		# ("/" for nfs://-URLS) are allowed
		#
		if (( ch_num > 127 )) || [[ "$ch" != ~(Elr)[/$-_.+!*\'(),[:alnum:]] ]] ; then
			url+="%$ch_hexval"
		else
			url+="$ch"
		fi
	done

	#printf 'str=%q\n' "$url"
	out_encodedstr="$url"
	return 0
}


function hostname_port_path_to_nfsurl
{
	set -o nounset

	typeset hostname="$1"
	integer port="$2"
	typeset path="$3"

	typeset enc_path
	typeset enc_hostname

	urlencodestr enc_hostname "$hostname"
	urlencodestr enc_path "$path"
	if (( port == 2049 )) ; then
		printf 'url=nfs://%s/%s\n' "$enc_hostname" "$enc_path"
	else
		printf 'url=nfs://%s:%d/%s\n' "$enc_hostname" port "$enc_path"
	fi
	return 0
}

function main
{
	set -o nounset

	# fixme: Need better text layout for $ nfsurlconv --man #
	typeset -r nfsurlconv_usage=$'+
	[-?\n@(#)\$Id: nfsurlconv (Roland Mainz) 2024-01-31 \$\n]
	[-author?Roland Mainz <roland.mainz@nrubsig.org>]
	[+NAME?nfsurlconv - convert hostname,port,path from/to a nfs://-URL]
	[+DESCRIPTION?\bnfsurlconv\b convert { hostname, port, path } from/to a nfs://-URL.]
	[D:debug?Enable debugging.]

	hostnameportpath2nfsurl hostname port path
	hostnamepath2nfsurl hostname path
	url2hostnameportpath url
	url2hostportpath url
	url2compound url
	--man

	[+EXAMPLES]{
		[+?Example 1:][+?Convert hostname bbb, port 12049 and path /a/b/c to a nfs://-URL]{
[+\n$ nfsurlconv hostnameportpath2nfsurl bbb 12049 "/a/b/c"
url=nfs:://bbb::12049//a/b/c
]
}
		[+?Example 2:][+?Convert URL nfs://bbb:12049//a/b/c to ( hostname=, port=, path= )]{
[+\n$ nfsurlconv.ksh url2hostnameportpath nfs:://bbb//a/b/c
hostname=bbb
port=2049
path=/a/b/c
]
}
		[+?Example 3:][+?Convert URL nfs://bbb:12049//a/b/c to ( hostport=, path= )]{
[+\n$ nfsurlconv.ksh url2hostportpath nfs:://bbb//a/b/c
hostport=bbb
path=/a/b/c
]
}
	}
	[+SEE ALSO?\bksh93\b(1),\bssh\b(1),\bmount.nfs\b(8),\bnfs\b(5)]
	'

	compound c
	typeset -a c.args
	integer saved_optind_m1	# saved OPTIND-1

	c.args=( "$@" )

	#
	# Argument parsing
	#
	while getopts -a "${progname}" "${nfsurlconv_usage}" OPT "${c.args[@]}" ; do
		case "${OPT}" in
			'D')
				# fixme: Implement debugging option
				;;
			*)
				usage "${progname}" "${nfsurlconv_usage}"
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

	typeset mode="${c.args[0]-}"

	case "$mode" in
		# fixme: add "hostportpath2nfsurl"
		# fixme: add "etcexports2nfsurl"
		'hostnameportpath2nfsurl')
			hostname_port_path_to_nfsurl "${@:2}"
			return $?
			;;
		'hostnamepath2nfsurl')
			hostname_port_path_to_nfsurl "${@:2:1}" 2049 "${@:3:1}"
			return $?
			;;
		'url2hostnameportpath')
			compound urldata

			parse_sshnfs_url urldata "${@:2:1}" || return 1
			printf 'hostname=%s\n' "${urldata.host}"
			printf 'port=%s\n' "${urldata.port-2049}"
			printf 'path=%s\n' "${urldata.path-}"
			return 0
			;;
		'url2hostportpath')
			compound urldata

			parse_sshnfs_url urldata "${@:2:1}" || return 1
			printf 'hostport=%s\n' "${urldata.hostport}"
			printf 'path=%s\n' "${urldata.path-}"
			return 0
			;;
		'url2compound')
			compound urldata

			parse_sshnfs_url urldata "${@:2:1}" || return 1
			print -v urldata
			return 0
			;;
		*)
			print -u2 -f $"Unknown mode %q\n" "$mode"
			usage "${progname}" "${nfsurlconv_usage}"
			return 2
			;;
	esac

	return 2
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
