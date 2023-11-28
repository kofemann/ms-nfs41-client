
/*
 * MIT License
 *
 * Copyright (c) 2023 Roland Mainz <roland.mainz@nrubsig.org>
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

/*
 * cpvparser1.h - simple ksh93 compound variable parsing
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
 * - multibyte characters
 *
 * Written by Roland Mainz <roland.mainz@nrubsig.org>
 */

#ifndef CPV_PARSER_H
#define CPV_PARSER_H 1

typedef struct cpv_name_val
{
	const char *cpv_name;
	const char *cpv_value;
} cpv_name_val;

/* Flags for |cpv_create_parser()| */
#define CPVFLAG_DEBUG_OUTPUT (0x00000008L)

/* prototypes */
void *cpv_create_parser(const char *s, unsigned long flags, ...);
void cpv_free_parser(void *);
int cpv_read_cpv_header(void *);
void cpv_free_name_val_data(cpv_name_val *);
int cpv_parse_name_val(void *, cpv_name_val *);

#endif /* !CPV_PARSER_H */
