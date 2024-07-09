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
#include <ctype.h>
#include <stdio.h>

// #define TEST_URLPARSER 1

#include "urlparser1.h"

typedef struct _url_parser_context_private {
	url_parser_context c;

	/* Private data */
	char *parameter_string_buff;
} url_parser_context_private;

#define MAX_URL_PARAMETERS 256

#ifdef _MSC_VER
/*
 * Disable "warning C4996: 'wcscpy': This function or variable may be
 * unsafe." because in this case the buffers are properly sized,
 * making this function safe
 */
#pragma warning (disable : 4996)
/*
 * Disable "warning C4706: assignment within conditional expression"
 * because it is safe to use in our code.
 */
#pragma warning (disable : 4706)
#endif /* _MSC_VER */

/*
 * Original extended regular expression:
 *
 * "^"
 * "(.+?)"				// scheme
 * "://"				// '://'
 * "("					// login
 *	"(?:"
 *	"(.+?)"				// user (optional)
 *		"(?::(.+))?"		// password (optional)
 *		"@"
 *	")?"
 *	"("				// hostport
 *		"(.+?)"			// host
 *		"(?::([[:digit:]]+))?"	// port (optional)
 *	")"
 * ")"
 * "(?:/(.*?))?"			// path (optional)
 * "(?:\?(.*?))?"			// URL parameters (optional)
 * "$"
 */

#define DBGNULLSTR(s) (((s)!=NULL)?(s):"<NULL>")
#if 0 || defined(TEST_URLPARSER)
#define D(x) x
#else
#define D(x)
#endif

static
void urldecodestr(char *outbuff, const char *buffer, size_t len)
{
	size_t i, j;

	for (i = j = 0 ; i < len ; ) {
		switch (buffer[i]) {
			case '%':
				if ((i + 2) < len) {
					if (isxdigit((int)buffer[i+1]) && isxdigit((int)buffer[i+2])) {
						const char hexstr[3] = {
							buffer[i+1],
							buffer[i+2],
							'\0'
						};
						outbuff[j++] = (unsigned char)strtol(hexstr, NULL, 16);
						i += 3;
					} else {
						/* invalid hex digit */
						outbuff[j++] = buffer[i];
						i++;
					}
				} else {
					/* incomplete hex digit */
					outbuff[j++] = buffer[i];
					i++;
				}
				break;
			case '+':
				outbuff[j++] = ' ';
				i++;
				break;
			default:
				outbuff[j++] = buffer[i++];
				break;
		}
	}

	outbuff[j] = '\0';
}

url_parser_context *url_parser_create_context(const char *in_url, unsigned int flags)
{
	url_parser_context_private *uctx;
	char *s;
	size_t in_url_len;
	size_t context_len;

	/* |flags| is for future extensions */
	(void)flags;

	if (!in_url)
		return NULL;

	in_url_len = strlen(in_url);

	context_len = sizeof(url_parser_context_private) +
		((in_url_len+1)*6) +
		(sizeof(url_parser_name_value)*MAX_URL_PARAMETERS)+sizeof(void*);
	uctx = malloc(context_len);
	if (!uctx)
		return NULL;

	s = (void *)(uctx+1);
	uctx->c.in_url = s;		s+= in_url_len+1;
	(void)strcpy(uctx->c.in_url, in_url);
	uctx->c.scheme = s;		s+= in_url_len+1;
	uctx->c.login.username = s;	s+= in_url_len+1;
	uctx->c.hostport.hostname = s;	s+= in_url_len+1;
	uctx->c.path = s;		s+= in_url_len+1;
	uctx->c.hostport.port = -1;
	uctx->c.num_parameters = -1;
	uctx->c.parameters = (void *)s;		s+= (sizeof(url_parser_name_value)*MAX_URL_PARAMETERS)+sizeof(void*);
	uctx->parameter_string_buff = s;	s+= in_url_len+1;

	return &uctx->c;
}

int url_parser_parse(url_parser_context *ctx)
{
	url_parser_context_private *uctx = (url_parser_context_private *)ctx;

	D((void)fprintf(stderr, "## parser in_url='%s'\n", uctx->c.in_url));

	char *s;
	const char *urlstr = uctx->c.in_url;
	size_t slen;

	s = strstr(urlstr, "://");
	if (!s) {
		D((void)fprintf(stderr, "url_parser: Not an URL\n"));
		return -1;
	}

	slen = s-urlstr;
	(void)memcpy(uctx->c.scheme, urlstr, slen);
	uctx->c.scheme[slen] = '\0';
	urlstr += slen + 3;

	D((void)fprintf(stdout, "scheme='%s', rest='%s'\n", uctx->c.scheme, urlstr));

	s = strstr(urlstr, "@");
	if (s) {
		/* URL has user/password */
		slen = s-urlstr;
		urldecodestr(uctx->c.login.username, urlstr, slen);
		urlstr += slen + 1;

		s = strstr(uctx->c.login.username, ":");
		if (s) {
			/* found passwd */
			uctx->c.login.passwd = s+1;
			*s = '\0';
		}
		else
		{
			uctx->c.login.passwd = NULL;
		}

		/* catch password-only URLs */
		if (uctx->c.login.username[0] == '\0')
			uctx->c.login.username = NULL;
	}
	else
	{
		uctx->c.login.username = NULL;
		uctx->c.login.passwd = NULL;
	}

	D((void)fprintf(stdout, "login='%s', passwd='%s', rest='%s'\n",
		DBGNULLSTR(uctx->c.login.username),
		DBGNULLSTR(uctx->c.login.passwd),
		DBGNULLSTR(urlstr)));

	char *raw_parameters;

	uctx->c.num_parameters = 0;
	raw_parameters = strstr(urlstr, "?");
	if (raw_parameters) {
		*raw_parameters++ = '\0';
		D((void)fprintf(stdout, "raw parameters = '%s'\n", raw_parameters));

		char *ps = raw_parameters;
		char *pv; /* parameter value */
		char *na; /* next '&' */
		char *pb = uctx->parameter_string_buff;
		char *pname;
		char *pvalue;
		ssize_t pi;

		for (pi = 0; pi < MAX_URL_PARAMETERS ; pi++) {
			pname = ps;

			/*
			 * Handle parameters without value,
			 * e.g. "path?name1&name2=value2"
			 */
			na = strstr(ps, "&");
			pv = strstr(ps, "=");
			if (pv && (na?(na > pv):true)) {
				*pv++ = '\0';
				pvalue = pv;
				ps = pv;
			}
			else {
				pvalue = NULL;
			}

			if (na) {
				*na++ = '\0';
			}

			/* URLDecode parameter name */
			urldecodestr(pb, pname, strlen(pname));
			uctx->c.parameters[pi].name = pb;
			pb += strlen(uctx->c.parameters[pi].name)+1;

			/* URLDecode parameter value */
			if (pvalue) {
				urldecodestr(pb, pvalue, strlen(pvalue));
				uctx->c.parameters[pi].value = pb;
				pb += strlen(uctx->c.parameters[pi].value)+1;
			}
			else {
				uctx->c.parameters[pi].value = NULL;
			}

			/* Next '&' ? */
			if (!na)
				break;

			ps = na;
		}

		uctx->c.num_parameters = pi+1;
	}

	s = strstr(urlstr, "/");
	if (s) {
		/* URL has hostport */
		slen = s-urlstr;
		urldecodestr(uctx->c.hostport.hostname, urlstr, slen);
		urlstr += slen + 1;

		/*
		 * check for addresses within '[' and ']', like
		 * IPv6 addresses
		 */
		s = uctx->c.hostport.hostname;
		if (s[0] == '[')
			s = strstr(s, "]");

		if (s == NULL) {
			D((void)fprintf(stderr, "url_parser: Unmatched '[' in hostname\n"));
			return -1;
		}

		s = strstr(s, ":");
		if (s) {
			/* found port number */
			uctx->c.hostport.port = atoi(s+1);
			*s = '\0';
		}
	}
	else
	{
		(void)strcpy(uctx->c.hostport.hostname, urlstr);
		uctx->c.path = NULL;
		urlstr = NULL;
	}

	D((void)fprintf(stdout, "hostport='%s', port=%d, rest='%s', num_parameters=%d\n",
		DBGNULLSTR(uctx->c.hostport.hostname),
		uctx->c.hostport.port,
		DBGNULLSTR(urlstr),
		(int)uctx->c.num_parameters));

	D(
		ssize_t dpi;
		for (dpi = 0 ; dpi < uctx->c.num_parameters ; dpi++) {
			(void)fprintf(stdout, "param[%d]: name='%s'/value='%s'\n",
				(int)dpi,
				uctx->c.parameters[dpi].name,
				DBGNULLSTR(uctx->c.parameters[dpi].value));
		}
	);

	if (!urlstr) {
		goto done;
	}

	urldecodestr(uctx->c.path, urlstr, strlen(urlstr));
	D((void)fprintf(stdout, "path='%s'\n", uctx->c.path));

done:
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
	(void)test_url_parser("foo://hostbar:93?param1");
	(void)test_url_parser("foo://hostbar:93?pname1=pvalue1");
	(void)test_url_parser("foo://hostbar:93?pname1=pvalue1&pname2=pvalue2");
	(void)test_url_parser("foo://hostbar:93?pname1=pvalue1&pvalue2=v2&n3=v3");
	(void)test_url_parser("foo://hostbar:93?pname1&param2=p2");
	(void)test_url_parser("foo://hostbar:93?pname1=&param2=p2");
	(void)test_url_parser("foo://hostbar:93//path/path2?param1=p1");
	(void)test_url_parser("foo://hostbar:93//path/path2?param1&param2=p2");
	(void)test_url_parser("foo://hostbar:93?pname1=pvalue1&%E2%82%AC=u+n2&n3=v3");
	(void)test_url_parser("foo://hostbar:93?pname1=pvalue1&%E2%82%AC=%E2%82%AC&n3=v3");

	(void)test_url_parser("foo://");
	(void)test_url_parser("typo:/hostbar");
	(void)test_url_parser("wrong");

	(void)puts("#done");

	return EXIT_SUCCESS;
}
#endif /* !TEST_URLPARSER */
