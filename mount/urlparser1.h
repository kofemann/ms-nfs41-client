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
