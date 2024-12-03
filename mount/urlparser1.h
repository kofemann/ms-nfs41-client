/*
 * MIT License
 *
 * Copyright (c) 2024 Roland Mainz <roland.mainz@nrubsig.org>
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
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* urlparser1.h - header for simple URL parser */

#ifndef __URLPARSER1_H__
#define __URLPARSER1_H__

#include <stdlib.h>

#ifdef _MSC_VER
typedef signed long long ssize_t;
#endif

typedef struct _url_parser_name_value {
	char *name;
	char *value;
} url_parser_name_value;

typedef struct _url_parser_context {
	char *in_url;

	char *scheme;
	struct {
		char *username;
		char *passwd;
	} login;
	struct {
		char *hostname;
		signed int port;
	} hostport;
	char *path;

	ssize_t num_parameters;
	url_parser_name_value *parameters;
} url_parser_context;

/* Prototypes */
url_parser_context *url_parser_create_context(const char *in_url, unsigned int flags);
int url_parser_parse(url_parser_context *uctx);
void url_parser_free_context(url_parser_context *c);

#endif /* !__URLPARSER1_H__ */
