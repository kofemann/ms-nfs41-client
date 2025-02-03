/* NFSv4.1 client for Windows
 * Copyright (C) 2012 The Regents of the University of Michigan
 * Copyright (C) 2023-2025 Roland Mainz <roland.mainz@nrubsig.org>
 *
 * Olga Kornievskaia <aglo@umich.edu>
 * Casey Bodley <cbodley@umich.edu>
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

#ifndef _KERNEL_MODE
#error module requires kernel mode
#endif

#if ((__STDC_VERSION__-0) < 201710L)
#error Code requires ISO C17
#endif

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

#define MINIRDR__NAME "Value is ignored, only fact of definition"
#include <rx.h>
#include <windef.h>
#include <winerror.h>

#include <Ntstrsafe.h>

#include "nfs41sys_buildconfig.h"

#include "nfs41_driver.h"
#include "nfs41sys_debug.h"
#include "nfs41_build_features.h"

#include "nfs41sys_driver.h"
#include "nfs41sys_util.h"

#include "win_reparse.h"



NTSTATUS nfs41_SetReparsePoint(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status;
    __notnull XXCTL_LOWIO_COMPONENT *FsCtl = &RxContext->LowIoContext.ParamsFor.FsCtl;
    __notnull PREPARSE_DATA_BUFFER Reparse = (PREPARSE_DATA_BUFFER)FsCtl->pInputBuffer;

    DbgEn();

    DbgP("nfs41_SetReparsePoint: ReparseTag: '%s'/0x%04lx\n",
        reparsetag2string(Reparse->ReparseTag),
        (long)Reparse->ReparseTag);

    switch(Reparse->ReparseTag) {
        case IO_REPARSE_TAG_SYMLINK:
            status = nfs41_SetSymlinkReparsePoint(RxContext);
            break;
        default:
            status = STATUS_NOT_IMPLEMENTED;
            DbgP("nfs41_SetReparsePoint: "
                "Unsupported ReparseTag: '%s'/0x%04lx\n",
                reparsetag2string(Reparse->ReparseTag),
                (long)Reparse->ReparseTag);
            break;
    }

    DbgEx();
    return status;
}


NTSTATUS nfs41_GetReparsePoint(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status;

    DbgEn();

    status = nfs41_GetSymlinkReparsePoint(RxContext);

    DbgEx();
    return status;
}
