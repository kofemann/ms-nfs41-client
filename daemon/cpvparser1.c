
/*
 * MIT License
 *
 * Copyright (c) 2023-2025 Roland Mainz <roland.mainz@nrubsig.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FORalloca ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * cpvparser1.c - simple ksh93 compound variable parsing
 *
 * It basically reads the output of $ print -v ... # like this:
 * ---- snip ----
 * $ ksh93 -c 'compound c=( va=1 vb=hello ) ; print -v c'
 * (
 *        va=1
 *        vb=hello
 * )
 * ---- snip ----
 *
 * ToDo:
 * - arrays (indexed, sparse indexed and associative)
 * - multibyte characters (e.g. use |wchar_t| API)
 *
 * Written by Roland Mainz <roland.mainz@nrubsig.org>
 */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "cpvparser1.h"

#ifdef _WIN32
#define strdup(s) _strdup(s)
#ifdef _MSC_VER
/*
 * Hack to avoid UCRT assertion
 * "minkernel\crts\ucrt\src\appcrt\convert\isctype.cpp(36) :
 * Assertion failed: c >= -1 && c <= 255"
 * This hack works for UTF-8 because UTF-8 and ASCII are identical for code
 * codepoints between 0 and 127 (i.e. UTF-8 is intentionally
 * backwards-compatible to ASCII).
 * Permanent fix would be to switch over to the |wchar_t| API.
 */
#undef isspace
#define isspace(c) isspace((((c) >= 0) && ((c) < 127))?(c):0)
#undef isalpha
#define isalpha(c) isalpha((((c) >= 0) && ((c) < 127))?(c):0)
#undef isalnum
#define isalnum(c) isalnum((((c) >= 0) && ((c) < 127))?(c):0)
#endif /* _MSC_VER */
#endif /* _WIN32 */

/* private data! */
typedef struct cpv_parse_context {
	const char *start_string;
	const char *curr_string;
	size_t max_name_val_size;
	unsigned long flags;
} cpv_parse_context;


void *cpv_create_parser(const char *s, unsigned long flags, ...)
{
	cpv_parse_context *cpc;

	cpc = calloc(1, sizeof(cpv_parse_context));
	if (!cpc)
		goto fail;

	cpc->start_string = strdup(s);
	if (!cpc->start_string)
		goto fail;

	cpc->curr_string = cpc->start_string;
	cpc->max_name_val_size = strlen(cpc->start_string);
	cpc->flags = flags;

	return (cpc);

fail:
	if (cpc) {
		free((void *)cpc->start_string);
		free(cpc);
	}

	return NULL;
}

void cpv_free_parser(void *v_cpc)
{
	cpv_parse_context *cpc = (cpv_parse_context *)v_cpc;
	if (cpc) {
		free((void *)cpc->start_string);
		free(cpc);
	}
}

int cpv_read_cpv_header(void *v_cpc)
{
	cpv_parse_context *cpc = (cpv_parse_context *)v_cpc;
	const char *s = cpc->curr_string;

skipspaces:
	while((*s != '\0') && isspace(*s))
		s++;

	/*
	 * skip POSIX-style '#' comments
	 * (allowed since this is based on POSIX sh(1) syntax)
	 */
	if (*s == '#') {
		s++;
		/* ignore everything until the end-of-line */
		while((*s != '\0') && (*s != '\n'))
			s++;
		goto skipspaces;
	}

	if (*s == '(') {
		cpc->curr_string=++s;
		if (cpc->flags & CPVFLAG_DEBUG_OUTPUT) {
			(void)fprintf(stderr, "cpv_read_cpv_header: begin-of-cpv\n");
		}
		return 0;
	}

	if (cpc->flags & CPVFLAG_DEBUG_OUTPUT) {
		(void)fprintf(stderr, "cpv_read_cpv_header: end-of-string, should not happen\n");
	}
	return 1;
}

int cpv_parse_name_val(void *v_cpc, cpv_name_val *cpv_nv)
{
	cpv_parse_context *cpc = (cpv_parse_context *)v_cpc;
#ifdef _WIN32
	char *namebuff = _alloca(cpc->max_name_val_size+1);
	char *valbuff  = _alloca(cpc->max_name_val_size+1);
#else
	char namebuff[cpc->max_name_val_size+1];
	char valbuff[cpc->max_name_val_size+1];
#endif

	const char *s = cpc->curr_string;

	char *n; /* pointer in |namebuff| */
	char *v; /* pointer in |valbuff| */

skipspaces:
	while((*s != '\0') && isspace(*s))
		s++;

	/*
	 * skip POSIX-style '#' comments
	 * (allowed since this is based on POSIX sh(1) syntax)
	 */
	if (*s == '#') {
		s++;
		/* ignore everything until the end-of-line */
		while((*s != '\0') && (*s != '\n'))
			s++;
		goto skipspaces;
	}

	if (*s == '\0') {
		if (cpc->flags & CPVFLAG_DEBUG_OUTPUT) {
			(void)fprintf(stderr, "cpv_parse_name_val: "
				"error: end-of-string, should not happen\n");
		}
		return 1;
	}

	/* cpv == "( foo=bar blabla=text )"*/
	if (*s == ')') {
		if (cpc->flags & CPVFLAG_DEBUG_OUTPUT) {
			(void)fprintf(stderr, "cpv_parse_name_val: end-of-cpv (OK)\n");
		}
		return 1;
	}

parse_varname:
	/*
	 * start parsing variable name
	 */

	/* variable names MUST start with a letter! */
	if (!isalpha(*s)) {
		if (cpc->flags & CPVFLAG_DEBUG_OUTPUT) {
			(void)fprintf(stderr,
				"cpv_parse_name_val: parser error, first char "
				"in variable name not isalpha(c=%c)\n",
				*s);
		}
		return 1;
	}

	n = namebuff;
	while((*s != '\0') && isalnum(*s))
		*n++ = *s++;
	*n = '\0';

	/*
	 * skip typed member varables
	 * (e.g. "typeset ", "typeset -i ", "typeset -l -i2" etc.)
	 */
	if (isspace(*s)) {
		if ((!strcmp(namebuff, "typeset")) ||
			(!strcmp(namebuff, "integer")) ||
			(!strcmp(namebuff, "float")) ||
			(!strcmp(namebuff, "compound"))) {
skip_typeset_options:
			while(isspace(*s))
				s++;
			if (*s == '-') {
				s++;
				while(isalnum(*s))
					s++;
				goto skip_typeset_options;
			}

			goto parse_varname;
		}
	}

	/* handle '=' */
	if (*s != '=') {
		if (cpc->flags & CPVFLAG_DEBUG_OUTPUT) {
			(void)fprintf(stderr, "cpv_parse_name_val: "
				"parser error, expected '=', got '%c'.\n",
				*s);
		}
		return 1;
	}

	s++; /* skip '=' */

	/*
	 * start parsing variable value
	 */
	bool in_doublequotes=false;
	bool in_singlequotes=false;
	v = valbuff;
val_quotes:
	if (in_singlequotes) {
		while(*s != '\0') {
			if (*s == '\'') {
				in_singlequotes = false;
				s++;
				goto val_quotes;
			}

			if ((*s == '\\') && (*(s+1) != '\0')) {
				/*
				 * fixme: should support \ooo octals,
				 * \u[hex] unicode and \w[hex] wchar
				 */
				s++;
			}
			*v++ = *s++;
		}
	}
	else if (in_doublequotes) {
		while(*s != '\0') {
			if (*s == '"') {
				in_doublequotes = false;
				s++;
				goto val_quotes;
			}

			if ((*s == '\\') && (*(s+1) != '\0')) {
				/*
				 * fixme: should support \ooo octals,
				 * \u[hex] unicode and \w[hex] wchar
				 */
				s++;
			}

			*v++ = *s++;
		}
	}
	else
	{
		while((*s != '\0') && (!isspace(*s))) {
			if (*s == '"') {
				in_doublequotes = true;
				s++;
				goto val_quotes;
			}

			if (*s == '\'') {
				in_singlequotes = true;
				s++;
				goto val_quotes;
			}

			if ((*s == '\\') && (*(s+1) != '\0')) {
				/*
				 * fixme: should support \ooo octals,
				 * \u[hex] unicode and \w[hex] wchar
				 */
				s++;
			}
			*v++ = *s++;
		}
	}

	if (in_singlequotes) {
		if (cpc->flags & CPVFLAG_DEBUG_OUTPUT) {
			(void)fprintf(stderr, "cpv_parse_name_val: "
				"parsererror, still in single quotes "
				"at the end\n");
		}
		return 1;
	}
	if (in_doublequotes) {
		if (cpc->flags & CPVFLAG_DEBUG_OUTPUT) {
			(void)fprintf(stderr, "cpv_parse_name_val: "
				"parser error, still in double quotes "
				"at the end\n");
		}
		return 1;
	}

	*v = '\0';

#if 0
	(void)printf("cpv_parse_name_val: name='%s', value='%s'\n",
		namebuff, valbuff);
#endif

	cpv_nv->cpv_name   = strdup(namebuff);
	cpv_nv->cpv_value  = strdup(valbuff);

	if ((cpv_nv->cpv_name == NULL) || (cpv_nv->cpv_value == NULL)) {
		cpv_free_name_val_data(cpv_nv);
		if (cpc->flags & CPVFLAG_DEBUG_OUTPUT) {
			(void)fprintf(stderr, "cpv_parse_name_val: "
				"parser error, out of memory\n");
		}
		return 2;
	}

	cpc->curr_string = s;

	return 0;
}

void cpv_free_name_val_data(cpv_name_val *cnv)
{
	if (!cnv)
		return;

	free((void *)cnv->cpv_name);
	free((void *)cnv->cpv_value);
	cnv->cpv_name = NULL;
	cnv->cpv_value = NULL;
}
