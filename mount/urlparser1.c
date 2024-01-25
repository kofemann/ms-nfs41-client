/*
 * NFSv4.1 client for Windows
 * Copyright (c) 2024 Roland Mainz <roland.mainz@nrubsig.org>
 *
 * Roland Mainz <roland.mainz@nrubsig.org>
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

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

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

#define DBGNULLSTR(s) (((s)!=NULL)?(s):"<NULL>")
#if 0
#define D(x) x
#else
#define D(x)
#endif

static
void urldecodestr(char *dst, const char *src, size_t len)
{
	/*
	 * Unicode characters with a code point > 255 are encoded
	 * as UTF-8 bytes
	 */
#define isurlxdigit(c) \
	(((c) >= '0' && (c) <= '9') || \
	((c) >= 'a' && (c) <= 'f') || \
	((c) >= 'A' && (c) <= 'F'))
	char a, b;
	while (*src && len--) {
		if (len > 2) {
			if ((*src == '%') &&
				(a = src[1]) && (b = src[2])) {
				if ((isurlxdigit(a) &&
					isurlxdigit(b))) {
					if (a >= 'a')
						a -= 'a'-'A';
					if (a >= 'A')
						a -= ('A' - 10);
					else
						a -= '0';

					if (b >= 'a')
						b -= 'a'-'A';
					if (b >= 'A')
						b -= ('A' - 10);
					else
						b -= '0';

					*dst++ = 16*a+b;

					src+=3;
					len-=2;
					continue;
				}
			}
                }
		if (*src == '+') {
			*dst++ = ' ';
			src++;
			continue;
                }
		*dst++ = *src++;
	}
	*dst++ = '\0';
}

url_parser_context *url_parser_create_context(const char *in_url, unsigned int flags)
{
	url_parser_context *uctx;
	char *s;
	size_t in_url_len;
	size_t context_len;

	if (!in_url)
		return NULL;

	in_url_len = strlen(in_url);

	context_len = sizeof(url_parser_context) +
		((in_url_len+1)*5);
	uctx = malloc(context_len);
	if (!uctx)
		return NULL;

	s = (void *)(uctx+1);
	uctx->in_url = s;		s+= in_url_len+1;
	(void)strcpy(uctx->in_url, in_url);
	uctx->scheme = s;		s+= in_url_len+1;
	uctx->login.username = s;	s+= in_url_len+1;
	uctx->hostport.hostname = s;	s+= in_url_len+1;
	uctx->path = s;			s+= in_url_len+1;
	uctx->hostport.port = -1;

	return uctx;
}

int url_parser_parse(url_parser_context *uctx)
{
	D((void)fprintf(stderr, "## parser in_url='%s'\n", uctx->in_url));

	char *s;
	const char *urlstr = uctx->in_url;
	size_t slen;

	s = strstr(urlstr, "://");
	if (!s) {
		D((void)fprintf(stderr, "url_parser: Not an URL\n"));
		return -1;
	}

	slen = s-urlstr;
	(void)memcpy(uctx->scheme, urlstr, slen);
	uctx->scheme[slen] = '\0';
	urlstr += slen + 3;

	D((void)fprintf(stdout, "scheme='%s', rest='%s'\n", uctx->scheme, urlstr));

	s = strstr(urlstr, "@");
	if (s) {
		/* URL has user/password */
		slen = s-urlstr;
		urldecodestr(uctx->login.username, urlstr, slen);
		urlstr += slen + 1;

		s = strstr(uctx->login.username, ":");
		if (s) {
			/* found passwd */
			uctx->login.passwd = s+1;
			*s = '\0';
		}
		else
		{
			uctx->login.passwd = NULL;
		}

		/* catch password-only URLs */
		if (uctx->login.username[0] == '\0')
			uctx->login.username = NULL;
	}
	else
	{
		uctx->login.username = NULL;
		uctx->login.passwd = NULL;
	}

	D((void)fprintf(stdout, "login='%s', passwd='%s', rest='%s'\n",
		DBGNULLSTR(uctx->login.username),
		DBGNULLSTR(uctx->login.passwd),
		DBGNULLSTR(urlstr)));

	s = strstr(urlstr, "/");
	if (s) {
		/* URL has hostport */
		slen = s-urlstr;
		urldecodestr(uctx->hostport.hostname, urlstr, slen);
		urlstr += slen + 1;

		/*
		 * check for addresses within '[' and ']', like
		 * IPv6 addresses
		 */
		s = uctx->hostport.hostname;
		if (s[0] == '[')
			s = strstr(s, "]");

		if (s == NULL) {
			D((void)fprintf(stderr, "url_parser: Unmatched '[' in hostname\n"));
			return -1;
		}

		s = strstr(s, ":");
		if (s) {
			/* found port number */
			uctx->hostport.port = atoi(s+1);
			*s = '\0';
		}
	}
	else
	{
		(void)strcpy(uctx->hostport.hostname, urlstr);
		uctx->path = NULL;
		urlstr = NULL;
	}

	D((void)fprintf(stdout, "hostport='%s', port=%d, rest='%s'\n",
		DBGNULLSTR(uctx->hostport.hostname),
		uctx->hostport.port,
		DBGNULLSTR(urlstr)));

	if (!urlstr) {
		return 0;
	}

	urldecodestr(uctx->path, urlstr, strlen(urlstr));
	D((void)fprintf(stdout, "path='%s'\n", uctx->path));

	return 0;
}

void url_parser_free_context(url_parser_context *c)
{
	free(c);
}

#ifdef TEST_URLPARSER
static
void test_url_parser(const char *instr)
{
	url_parser_context *c;

	c = url_parser_create_context(instr, 0);

	(void)url_parser_parse(c);

	(void)fputc('\n', stdout);

	url_parser_free_context(c);
}

int main(int ac, char *av[])
{
	(void)puts("#start");

	(void)setvbuf(stdout, NULL, _IONBF, 0);
	(void)setvbuf(stderr, NULL, _IONBF, 0);

	(void)test_url_parser("foo://hostbar/baz");
	(void)test_url_parser("foo://myuser@hostbar/baz");
	(void)test_url_parser("foo://myuser:mypasswd@hostbar/baz");
	(void)test_url_parser("foo://Vorname+Nachname:mypasswd@hostbar/baz");
	(void)test_url_parser("foo://Vorname%20Nachname:mypasswd@hostbar/baz%");
	(void)test_url_parser("foo://myuser:mypasswd@hostbar:666/baz");
	(void)test_url_parser("foo://myuser:mypasswd@hostbar:666//baz");
	(void)test_url_parser("foo://myuser:mypasswd@[fe80::21b:1bff:fec3:7713]:666/baz");
	(void)test_url_parser("foo://:mypasswd2@hostbar2:667/baf");
	(void)test_url_parser("foo://hostbar/euro/symbol/%E2%82%AC/here");
	(void)test_url_parser("foo://hostbar");
	(void)test_url_parser("foo://hostbar:93");
	(void)test_url_parser("nfs://hostbar:93/relativepath/a");
	(void)test_url_parser("nfs://hostbar:93//absolutepath/a");
	(void)test_url_parser("nfs://hostbar:93//absolutepath/blank%20path/a");
	(void)test_url_parser("nfs://hostbar:93//absolutepath/blank+path/a");


	(void)test_url_parser("foo://");
	(void)test_url_parser("typo:/hostbar");
	(void)test_url_parser("wrong");

	(void)puts("#done");

	return EXIT_SUCCESS;
}
#endif /* !TEST_URLPARSER */
