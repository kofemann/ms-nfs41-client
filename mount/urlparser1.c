/* NFSv4.1 client for Windows
 * Copyright (c) 2024 Roland Mainz <roland.mainz@nrubsig.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * without any warranty; without even the implied warranty of merchantability
 * or fitness for a particular purpose.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 */


/* urlparser1.c - simple URL parser */

#if ((__STDC_VERSION__-0) < 201710L)
#error Code requires ISO C17
#endif


#include <crtdbg.h>
#include <Windows.h>
#include <stdlib.h>

#include "urlparser1.h"

/*
 * Disable "warning C4996: 'wcscpy': This function or variable may be
 * unsafe." because in this case the buffers are properly sized,
 * making this function safe
 */
#pragma warning (disable : 4996)

/*
 * Original extended regular expression:
 *
 * "^"
 * "(.+?)"			 // scheme
 * "://"  			 // '://'
 * "("				 // login
 * 	 "(?:"
 * 		 "(.+?)"	 // user (optional)
 * 		 "(?::(.+))?"	 // password (optional)
 * 		 "@"
 * 	 ")?"
 * 	 "("			 // hostport
 * 		 "(.+?)"	 // host
 * 		 "(?::([[:digit:]]+))?" // port (optional)
 * 	 ")"
 * ")"
 * "(?:/(.*?))?"  		 // path (optional)
 * "$"
 */

#define DBGNULLSTR(s) (((s)!=NULL)?(s):TEXT("<NULL>"))
#if 0
#define D(x) x
#else
#define D(x)
#endif

url_parser_context *url_parser_create_context(const TCHAR *in_url, unsigned int flags)
{
	url_parser_context *uctx;
	TCHAR *s;
	size_t in_url_len;
	size_t context_len;

	if (!in_url)
		return NULL;

	in_url_len = _tcsclen(in_url);

	context_len = sizeof(url_parser_context) +
		(((in_url_len+1)*5L*sizeof(TCHAR)));
	uctx = malloc(context_len);
	if (!uctx)
		return NULL;

	s = (void *)(uctx+1);
	uctx->in_url = s;		s+= in_url_len+1;
	(void)_tcscpy(uctx->in_url, in_url);
	uctx->scheme = s;		s+= in_url_len+1;
	uctx->login.username = s;	s+= in_url_len+1;
	uctx->hostport.hostname = s;	s+= in_url_len+1;
	uctx->path = s;			s+= in_url_len+1;
	uctx->hostport.port = -1;

	return uctx;
}

int url_parser_parse(url_parser_context *uctx)
{
	D((void)_tprintf(TEXT("## parser in_url='%s'\n"), uctx->in_url));

	TCHAR *s;
	const TCHAR *urlstr = uctx->in_url;
	size_t slen;

	s = _tcsstr(urlstr, TEXT("://"));
	if (!s) {
		D((void)_tprintf(TEXT("url_parser: Not an URL\n")));
		return -1;
	}

	slen = s-urlstr;
	(void)memcpy(uctx->scheme, urlstr, slen*sizeof(TCHAR));
	uctx->scheme[slen] = TEXT('\0');
	urlstr += slen + 3;

	D((void)_tprintf(TEXT("scheme='%s', rest='%s'\n"), uctx->scheme, urlstr));

	s = _tcsstr(urlstr, TEXT("@"));
	if (s) {
		/* URL has user/password */
		slen = s-urlstr;
		(void)memcpy(uctx->login.username, urlstr, slen*sizeof(TCHAR));
		uctx->login.username[slen] = TEXT('\0');
		urlstr += slen + 1;

		s = _tcsstr(uctx->login.username, TEXT(":"));
		if (s) {
			/* found passwd */
			uctx->login.passwd = s+1;
			*s = TEXT('\0');
		}
		else
		{
			uctx->login.passwd = NULL;
		}

		/* catch password-only URLs */
		if (uctx->login.username[0] == TEXT('\0'))
			uctx->login.username = NULL;
	}
	else
	{
		uctx->login.username = NULL;
		uctx->login.passwd = NULL;
	}

	D((void)_tprintf(TEXT("login='%s', passwd='%s', rest='%s'\n"),
		DBGNULLSTR(uctx->login.username),
		DBGNULLSTR(uctx->login.passwd),
		DBGNULLSTR(urlstr)));

	s = _tcsstr(urlstr, TEXT("/"));
	if (s) {
		/* URL has hostport */
		slen = s-urlstr;
		(void)memcpy(uctx->hostport.hostname, urlstr, slen*sizeof(TCHAR));
		uctx->hostport.hostname[slen] = TEXT('\0');
		urlstr += slen;

		/*
		 * check for addresses within '[' and ']', like
		 * IPv6 addresses
		 */
		s = uctx->hostport.hostname;
		if (s[0] == TEXT('['))
			s = _tcsstr(s, TEXT("]"));

		if (s == NULL) {
			D((void)_tprintf(TEXT("url_parser: Unmatched '[' in hostname\n")));
			return -1;
		}

		s = _tcsstr(s, TEXT(":"));
		if (s) {
			/* found port number */
			uctx->hostport.port = _tstoi(s+1);
			*s = TEXT('\0');
		}
	}
	else
	{
		(void)_tcscpy(uctx->hostport.hostname, urlstr);
		uctx->path = NULL;
		urlstr = NULL;
	}

	D((void)_tprintf(TEXT("hostport='%s', port=%d, rest='%s'\n"),
		DBGNULLSTR(uctx->hostport.hostname),
		uctx->hostport.port,
		DBGNULLSTR(urlstr)));

	if (!urlstr) {
		return 0;
	}

	(void)_tcscpy(uctx->path, urlstr);
	D((void)_tprintf(TEXT("path='%s'\n"), uctx->path));

	return 0;
}

void url_parser_free_context(url_parser_context *c)
{
	free(c);
}
