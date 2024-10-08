/* NFSv4.1 client for Windows
 * Copyright © 2012 The Regents of the University of Michigan
 *
 * Olga Kornievskaia <aglo@umich.edu>
 * Casey Bodley <cbodley@umich.edu>
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
 *
 * Comments: RDBSS depends on wmlkm files. See comments in nulmrx/wmlkm
 */

#pragma hdrstop

/* FIXME: Why does VS22 need this, but not VC19 ? */
#if _MSC_VER >= 1900
#if defined(_WIN64) && defined(_M_X64)
#ifndef _AMD64_
#define _AMD64_
#endif
#elif defined(_WIN32) && defined(_M_IX86)
#ifndef _X86_
#define _X86_
#endif
#elif defined(_WIN64) && defined(_M_ARM64)
#ifndef _ARM64_
#define _ARM64_
#endif
#elif defined(_WIN32) && defined(_M_ARM)
#ifndef _ARM_
#define _ARM_
#endif
#else
#error Unsupported arch
#endif
#endif /* _MSC_VER >= 1900 */



#include <ntddk.h>
#include <ntdef.h>
#define LPVOID PVOID64 // BUG - need to find include for this
#include "wmlkm.h"

NTSTATUS
WmlTinySystemControl(
    __inout PVOID WmiLibInfo,
    __in PVOID DeviceObject,
    __in PVOID Irp
    )
{
    return(STATUS_WMI_GUID_NOT_FOUND);
}

ULONG
WmlTrace(
    __in ULONG Type,
    __in LPVOID TraceGuid,
    __in ULONG64 LoggerHandle,
    ... // Pairs: Address, Length
    )
{
    return STATUS_SUCCESS;
}