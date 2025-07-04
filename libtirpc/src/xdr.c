/*
 * Copyright (c) 2009, Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of Sun Microsystems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


/*
 * xdr.c, Generic XDR routines implementation.
 *
 * Copyright (C) 1986, Sun Microsystems, Inc.
 *
 * These are the "generic" xdr routines used to serialize and de-serialize
 * most common data items.  See xdr.h for more info on the interface to
 * xdr.
 */

#include <wintirpc.h>
//#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rpc/rpc.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/rpc_com.h>

typedef quad_t          longlong_t;     /* ANSI long long type */
typedef u_quad_t        u_longlong_t;   /* ANSI unsigned long long type */

/*
 * constants specific to the xdr "protocol"
 */
#define XDR_FALSE	((long) 0)
#define XDR_TRUE	((long) 1)

/*
 * for unit alignment
 */
static const char xdr_zero[BYTES_PER_XDR_UNIT] = { 0, 0, 0, 0 };

/*
 * Free a data structure using XDR
 * Not a filter, but a convenient utility nonetheless
 */
void
xdr_free(proc, objp)
	xdrproc_t proc;
	void *objp;
{
	XDR x;
	
	x.x_op = XDR_FREE;
	(*proc)(&x, objp);
}

/*
 * XDR nothing
 */
bool_t
xdr_void(void)
{

	return (TRUE);
}


/*
 * XDR integers
 */
bool_t
xdr_int(xdrs, ip)
	XDR *xdrs;
	int *ip;
{
	long l;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (long) *ip;
		return (XDR_PUTLONG(xdrs, &l));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, &l)) {
			return (FALSE);
		}
		*ip = (int) l;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	/* NOTREACHED */
	return (FALSE);
}

/*
 * XDR unsigned integers
 */
bool_t
xdr_u_int(xdrs, up)
	XDR *xdrs;
	u_int *up;
{
	u_long l;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (u_long) *up;
		return (XDR_PUTLONG(xdrs, (long *)&l));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, (long *)&l)) {
			return (FALSE);
		}
		*up = (u_int) l;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	/* NOTREACHED */
	return (FALSE);
}


/*
 * XDR long integers
 * same as xdr_u_long - open coded to save a proc call!
 */
bool_t
xdr_long(xdrs, lp)
	XDR *xdrs;
	long *lp;
{
	switch (xdrs->x_op) {
	case XDR_ENCODE:
		return (XDR_PUTLONG(xdrs, lp));
	case XDR_DECODE:
		return (XDR_GETLONG(xdrs, lp));
	case XDR_FREE:
		return (TRUE);
	}
	/* NOTREACHED */
	return (FALSE);
}

/*
 * XDR unsigned long integers
 * same as xdr_long - open coded to save a proc call!
 */
bool_t
xdr_u_long(xdrs, ulp)
	XDR *xdrs;
	u_long *ulp;
{
	switch (xdrs->x_op) {
	case XDR_ENCODE:
		return (XDR_PUTLONG(xdrs, (long *)ulp));
	case XDR_DECODE:
		return (XDR_GETLONG(xdrs, (long *)ulp));
	case XDR_FREE:
		return (TRUE);
	}
	/* NOTREACHED */
	return (FALSE);
}


/*
 * XDR 32-bit integers
 * same as xdr_u_int32_t - open coded to save a proc call!
 */
bool_t
xdr_int32_t(xdrs, int32_p)
	XDR *xdrs;
	int32_t *int32_p;
{
	long l;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (long) *int32_p;
		return (XDR_PUTLONG(xdrs, &l));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, &l)) {
			return (FALSE);
		}
		*int32_p = (int32_t) l;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	/* NOTREACHED */
	return (FALSE);
}

/*
 * XDR unsigned 32-bit integers
 * same as xdr_int32_t - open coded to save a proc call!
 */
bool_t
xdr_u_int32_t(xdrs, u_int32_p)
	XDR *xdrs;
	u_int32_t *u_int32_p;
{
	u_long l;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (u_long) *u_int32_p;
		return (XDR_PUTLONG(xdrs, (long *)&l));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, (long *)&l)) {
			return (FALSE);
		}
		*u_int32_p = (u_int32_t) l;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	/* NOTREACHED */
	return (FALSE);
}


/*
 * XDR unsigned 32-bit integers
 */
bool_t
xdr_uint32_t(xdrs, uint32_p)
	XDR *xdrs;
	uint32_t *uint32_p;
{
	return (xdr_u_int32_t(xdrs, (u_int32_t *)uint32_p));
}


/*
 * XDR short integers
 */
bool_t
xdr_short(xdrs, sp)
	XDR *xdrs;
	short *sp;
{
	long l;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (long) *sp;
		return (XDR_PUTLONG(xdrs, &l));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, &l)) {
			return (FALSE);
		}
		*sp = (short) l;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	/* NOTREACHED */
	return (FALSE);
}

/*
 * XDR unsigned short integers
 */
bool_t
xdr_u_short(xdrs, usp)
	XDR *xdrs;
	u_short *usp;
{
	u_long l;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (u_long) *usp;
		return (XDR_PUTLONG(xdrs, (long *)&l));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, (long *)&l)) {
			return (FALSE);
		}
		*usp = (u_short) l;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	/* NOTREACHED */
	return (FALSE);
}


/*
 * XDR 16-bit integers
 */
bool_t
xdr_int16_t(xdrs, int16_p)
	XDR *xdrs;
	int16_t *int16_p;
{
	long l;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (long) *int16_p;
		return (XDR_PUTLONG(xdrs, &l));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, &l)) {
			return (FALSE);
		}
		*int16_p = (int16_t) l;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	/* NOTREACHED */
	return (FALSE);
}

/*
 * XDR unsigned 16-bit integers
 */
bool_t
xdr_u_int16_t(xdrs, u_int16_p)
	XDR *xdrs;
	u_int16_t *u_int16_p;
{
	u_long l;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (u_long) *u_int16_p;
		return (XDR_PUTLONG(xdrs, (long *)&l));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, (long *)&l)) {
			return (FALSE);
		}
		*u_int16_p = (u_int16_t) l;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	/* NOTREACHED */
	return (FALSE);
}


/*
 * XDR unsigned 16-bit integers
 */
bool_t
xdr_uint16_t(xdrs, uint16_p)
	XDR *xdrs;
	uint16_t *uint16_p;
{
	return (xdr_u_int16_t(xdrs, (u_int16_t *)uint16_p));
}


/*
 * XDR 8-bit integers
 */
bool_t
xdr_int8_t(xdrs, int8_p)
	XDR *xdrs;
	int8_t *int8_p;
{
	long l;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (long) *int8_p;
		return (XDR_PUTLONG(xdrs, &l));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, &l)) {
			return (FALSE);
		}
		*int8_p = (int8_t) l;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	/* NOTREACHED */
	return (FALSE);
}


/*
 * XDR unsigned 8-bit integers
 */
bool_t
xdr_u_int8_t(xdrs, uint8_p)
	XDR *xdrs;
	uint8_t *uint8_p;
{
	u_long l;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		l = (u_long) *uint8_p;
		return (XDR_PUTLONG(xdrs, (long *)&l));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, (long *)&l)) {
			return (FALSE);
		}
		*uint8_p = (uint8_t) l;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	/* NOTREACHED */
	return (FALSE);
}


/*
 * XDR unsigned 8-bit integers
 */
bool_t
xdr_uint8_t(xdrs, uint8_p)
	XDR *xdrs;
	uint8_t *uint8_p;
{
	return (xdr_u_int8_t(xdrs, (uint8_t *)uint8_p));
}


/*
 * XDR a char
 */
bool_t
xdr_char(xdrs, cp)
	XDR *xdrs;
	char *cp;
{
	int i;

	i = (*cp);
	if (!xdr_int(xdrs, &i)) {
		return (FALSE);
	}
	*cp = (char)i;
	return (TRUE);
}

/*
 * XDR an unsigned char
 */
bool_t
xdr_u_char(xdrs, cp)
	XDR *xdrs;
	u_char *cp;
{
	u_int u;

	u = (*cp);
	if (!xdr_u_int(xdrs, &u)) {
		return (FALSE);
	}
	*cp = (u_char)u;
	return (TRUE);
}

/*
 * XDR booleans
 */
bool_t
xdr_bool(xdrs, bp)
	XDR *xdrs;
	bool_t *bp;
{
	long lb;

	switch (xdrs->x_op) {

	case XDR_ENCODE:
		lb = *bp ? XDR_TRUE : XDR_FALSE;
		return (XDR_PUTLONG(xdrs, &lb));

	case XDR_DECODE:
		if (!XDR_GETLONG(xdrs, &lb)) {
			return (FALSE);
		}
		*bp = (lb == XDR_FALSE) ? FALSE : TRUE;
		return (TRUE);

	case XDR_FREE:
		return (TRUE);
	}
	/* NOTREACHED */
	return (FALSE);
}

/*
 * XDR enumerations
 */
bool_t
xdr_enum(xdrs, ep)
	XDR *xdrs;
	enum_t *ep;
{
	enum sizecheck { SIZEVAL };	/* used to find the size of an enum */

#ifdef _WIN32
#pragma warning( push )
/*
 * warning C4127: conditional expression is constant
 */
#pragma warning (disable : 4127)
#endif /* _WIN32 */
	/*
	 * enums are treated as ints
	 */
	/* LINTED */ if (sizeof (enum sizecheck) == sizeof (long)) {
		return (xdr_long(xdrs, (long *)(void *)ep));
	} else /* LINTED */ if (sizeof (enum sizecheck) == sizeof (int)) {
		return (xdr_int(xdrs, (int *)(void *)ep));
	} else /* LINTED */ if (sizeof (enum sizecheck) == sizeof (short)) {
		return (xdr_short(xdrs, (short *)(void *)ep));
	} else {
		return (FALSE);
	}
#ifdef _WIN32
#pragma warning( pop )
#endif /* _WIN32 */
}

/*
 * XDR opaque data
 * Allows the specification of a fixed size sequence of opaque bytes.
 * cp points to the opaque object and cnt gives the byte length.
 */
bool_t
xdr_opaque(xdrs, cp, cnt)
	XDR *xdrs;
	caddr_t cp;
	u_int cnt;
{
	u_int rndup;
	static int crud[BYTES_PER_XDR_UNIT];

	/*
	 * if no data we are done
	 */
	if (cnt == 0)
		return (TRUE);

	/*
	 * round byte count to full xdr units
	 */
	rndup = cnt % BYTES_PER_XDR_UNIT;
	if (rndup > 0)
		rndup = BYTES_PER_XDR_UNIT - rndup;

	if (xdrs->x_op == XDR_DECODE) {
		if (!XDR_GETBYTES(xdrs, cp, cnt)) {
			return (FALSE);
		}
		if (rndup == 0)
			return (TRUE);
		return (XDR_GETBYTES(xdrs, (caddr_t)(void *)crud, rndup));
	}

	if (xdrs->x_op == XDR_ENCODE) {
		if (!XDR_PUTBYTES(xdrs, cp, cnt)) {
			return (FALSE);
		}
		if (rndup == 0)
			return (TRUE);
		return (XDR_PUTBYTES(xdrs, xdr_zero, rndup));
	}

	if (xdrs->x_op == XDR_FREE) {
		return (TRUE);
	}

	return (FALSE);
}

/*
 * XDR counted bytes
 * *cpp is a pointer to the bytes, *sizep is the count.
 * If *cpp is NULL maxsize bytes are allocated
 */
bool_t
xdr_bytes(xdrs, cpp, sizep, maxsize)
	XDR *xdrs;
	char **cpp;
	u_int *sizep;
	u_int maxsize;
{
	char *sp = *cpp;  /* sp is the actual string pointer */
	u_int nodesize;
	bool_t ret, allocated = FALSE;

	/*
	 * first deal with the length since xdr bytes are counted
	 */
	if (! xdr_u_int(xdrs, sizep)) {
		return (FALSE);
	}
	nodesize = *sizep;
	if ((nodesize > maxsize) && (xdrs->x_op != XDR_FREE)) {
		return (FALSE);
	}

	/*
	 * now deal with the actual bytes
	 */
	switch (xdrs->x_op) {

	case XDR_DECODE:
		if (nodesize == 0) {
			return (TRUE);
		}
		if (sp == NULL) {
			*cpp = sp = mem_alloc(nodesize);
			allocated = TRUE;
		}
		if (sp == NULL) {
			warnx("xdr_bytes: out of memory");
			return (FALSE);
		}
		/* FALLTHROUGH */

	case XDR_ENCODE:
		ret = xdr_opaque(xdrs, sp, nodesize);
		if ((xdrs->x_op == XDR_DECODE) && (ret == FALSE)) {
			if (allocated == TRUE) {
				free(sp);
				*cpp = NULL;
			}
		}
		return (ret);

	case XDR_FREE:
		if (sp != NULL) {
			mem_free(sp, nodesize);
			*cpp = NULL;
		}
		return (TRUE);
	}
	/* NOTREACHED */
	return (FALSE);
}

/*
 * Implemented here due to commonality of the object.
 */
bool_t
xdr_netobj(xdrs, np)
	XDR *xdrs;
	struct netobj *np;
{

	return (xdr_bytes(xdrs, &np->n_bytes, &np->n_len, MAX_NETOBJ_SZ));
}

/*
 * XDR a descriminated union
 * Support routine for discriminated unions.
 * You create an array of xdrdiscrim structures, terminated with
 * an entry with a null procedure pointer.  The routine gets
 * the discriminant value and then searches the array of xdrdiscrims
 * looking for that value.  It calls the procedure given in the xdrdiscrim
 * to handle the discriminant.  If there is no specific routine a default
 * routine may be called.
 * If there is no specific or default routine an error is returned.
 */
bool_t
xdr_union(xdrs, dscmp, unp, choices, dfault)
	XDR *xdrs;
	enum_t *dscmp;		/* enum to decide which arm to work on */
	char *unp;		/* the union itself */
	const struct xdr_discrim *choices;	/* [value, xdr proc] for each arm */
	xdrproc_t dfault;	/* default xdr routine */
{
	enum_t dscm;

	/*
	 * we deal with the discriminator;  it's an enum
	 */
	if (! xdr_enum(xdrs, dscmp)) {
		return (FALSE);
	}
	dscm = *dscmp;

	/*
	 * search choices for a value that matches the discriminator.
	 * if we find one, execute the xdr routine for that value.
	 */
	for (; choices->proc != NULL_xdrproc_t; choices++) {
		if (choices->value == dscm)
			return ((*(choices->proc))(xdrs, unp));
	}

	/*
	 * no match - execute the default xdr routine if there is one
	 */
	return ((dfault == NULL_xdrproc_t) ? FALSE :
	    (*dfault)(xdrs, unp));
}


/*
 * Non-portable xdr primitives.
 * Care should be taken when moving these routines to new architectures.
 */


/*
 * XDR null terminated ASCII strings
 * xdr_string deals with "C strings" - arrays of bytes that are
 * terminated by a NULL character.  The parameter cpp references a
 * pointer to storage; If the pointer is null, then the necessary
 * storage is allocated.  The last parameter is the max allowed length
 * of the string as specified by a protocol.
 */
bool_t
xdr_string(xdrs, cpp, maxsize)
	XDR *xdrs;
	char **cpp;
	u_int maxsize;
{
	char *sp = *cpp;  /* sp is the actual string pointer */
	u_int size;
	u_int nodesize;
	bool_t ret, allocated = FALSE;

	/*
	 * first deal with the length since xdr strings are counted-strings
	 */
	switch (xdrs->x_op) {
	case XDR_FREE:
		if (sp == NULL) {
			return(TRUE);	/* already free */
		}
		/* FALLTHROUGH */
	case XDR_ENCODE:
		if (sp == NULL)
			return FALSE;
		size = (u_int)strlen(sp);
		break;
	case XDR_DECODE:
		break;
	}
	if (! xdr_u_int(xdrs, &size)) {
		return (FALSE);
	}
	if (size > maxsize) {
		return (FALSE);
	}
	nodesize = size + 1;
	if (nodesize == 0) {
		/* This means an overflow.  It a bug in the caller which
		 * provided a too large maxsize but nevertheless catch it
		 * here.
		 */
		return FALSE;
	}

	/*
	 * now deal with the actual bytes
	 */
	switch (xdrs->x_op) {

	case XDR_DECODE:
		if (sp == NULL) {
			*cpp = sp = mem_alloc(nodesize);
			allocated = TRUE;
		}
		if (sp == NULL) {
			warnx("xdr_string: out of memory");
			return (FALSE);
		}
		sp[size] = 0;
		/* FALLTHROUGH */

	case XDR_ENCODE:
		ret = xdr_opaque(xdrs, sp, size);
		if ((xdrs->x_op == XDR_DECODE) && (ret == FALSE)) {
			if (allocated == TRUE) {
				free(sp);
				*cpp = NULL;
			}
		}
		return (ret);

	case XDR_FREE:
		mem_free(sp, nodesize);
		*cpp = NULL;
		return (TRUE);
	}
	/* NOTREACHED */
	return (FALSE);
}

/*
 * Wrapper for xdr_string that can be called directly from
 * routines like clnt_call
 */
bool_t
xdr_wrapstring(xdrs, cpp)
	XDR *xdrs;
	char **cpp;
{
	return xdr_string(xdrs, cpp, RPC_MAXDATASIZE);
}

/*
 * NOTE: xdr_hyper(), xdr_u_hyper(), xdr_longlong_t(), and xdr_u_longlong_t()
 * are in the "non-portable" section because they require that a `long long'
 * be a 64-bit type.
 *
 *	--thorpej@netbsd.org, November 30, 1999
 */

/*
 * XDR 64-bit integers
 */
bool_t
xdr_int64_t(xdrs, llp)
	XDR *xdrs;
	int64_t *llp;
{
	u_long ul[2];

	switch (xdrs->x_op) {
	case XDR_ENCODE:
		ul[0] = (u_long)((u_int64_t)*llp >> 32) & 0xffffffff;
		ul[1] = (u_long)((u_int64_t)*llp) & 0xffffffff;
		if (XDR_PUTLONG(xdrs, (long *)&ul[0]) == FALSE)
			return (FALSE);
		return (XDR_PUTLONG(xdrs, (long *)&ul[1]));
	case XDR_DECODE:
		if (XDR_GETLONG(xdrs, (long *)&ul[0]) == FALSE)
			return (FALSE);
		if (XDR_GETLONG(xdrs, (long *)&ul[1]) == FALSE)
			return (FALSE);
		*llp = (int64_t)
		    (((u_int64_t)ul[0] << 32) |
		     ((u_int64_t)(ul[1]) & 0xffffffff));
		return (TRUE);
	case XDR_FREE:
		return (TRUE);
	}
	/* NOTREACHED */
	return (FALSE);
}


/*
 * XDR unsigned 64-bit integers
 */
bool_t
xdr_u_int64_t(xdrs, ullp)
	XDR *xdrs;
	u_int64_t *ullp;
{
	u_long ul[2];

	switch (xdrs->x_op) {
	case XDR_ENCODE:
		ul[0] = (u_long)(*ullp >> 32) & 0xffffffff;
		ul[1] = (u_long)(*ullp) & 0xffffffff;
		if (XDR_PUTLONG(xdrs, (long *)&ul[0]) == FALSE)
			return (FALSE);
		return (XDR_PUTLONG(xdrs, (long *)&ul[1]));
	case XDR_DECODE:
		if (XDR_GETLONG(xdrs, (long *)&ul[0]) == FALSE)
			return (FALSE);
		if (XDR_GETLONG(xdrs, (long *)&ul[1]) == FALSE)
			return (FALSE);
		*ullp = (u_int64_t)
		    (((u_int64_t)ul[0] << 32) |
		     ((u_int64_t)(ul[1]) & 0xffffffff));
		return (TRUE);
	case XDR_FREE:
		return (TRUE);
	}
	/* NOTREACHED */
	return (FALSE);
}


/*
 * XDR unsigned 64-bit integers
 */
bool_t
xdr_uint64_t(xdrs, ullp)
	XDR *xdrs;
	uint64_t *ullp;
{
	return (xdr_u_int64_t(xdrs, (u_int64_t *)ullp));
}


/*
 * XDR hypers
 */
bool_t
xdr_hyper(xdrs, llp)
	XDR *xdrs;
	longlong_t *llp;
{

	/*
	 * Don't bother open-coding this; it's a fair amount of code.  Just
	 * call xdr_int64_t().
	 */
	return (xdr_int64_t(xdrs, (int64_t *)llp));
}


/*
 * XDR unsigned hypers
 */
bool_t
xdr_u_hyper(xdrs, ullp)
	XDR *xdrs;
	u_longlong_t *ullp;
{

	/*
	 * Don't bother open-coding this; it's a fair amount of code.  Just
	 * call xdr_u_int64_t().
	 */
	return (xdr_u_int64_t(xdrs, (u_int64_t *)ullp));
}


/*
 * XDR longlong_t's
 */
bool_t
xdr_longlong_t(xdrs, llp)
	XDR *xdrs;
	longlong_t *llp;
{

	/*
	 * Don't bother open-coding this; it's a fair amount of code.  Just
	 * call xdr_int64_t().
	 */
	return (xdr_int64_t(xdrs, (int64_t *)llp));
}


/*
 * XDR u_longlong_t's
 */
bool_t
xdr_u_longlong_t(xdrs, ullp)
	XDR *xdrs;
	u_longlong_t *ullp;
{

	/*
	 * Don't bother open-coding this; it's a fair amount of code.  Just
	 * call xdr_u_int64_t().
	 */
	return (xdr_u_int64_t(xdrs, (u_int64_t *)ullp));
}

/*
 * XDR quad_t
 */
bool_t
xdr_quad_t(xdrs, llp)
	XDR *xdrs;
	int64_t *llp;
{
	return (xdr_int64_t(xdrs, (int64_t *)llp));
}


/*
 * XDR u_quad_t
 */
bool_t
xdr_u_quad_t(xdrs, ullp)
	XDR *xdrs;
	u_int64_t *ullp;
{
	return (xdr_u_int64_t(xdrs, (u_int64_t *)ullp));
}
