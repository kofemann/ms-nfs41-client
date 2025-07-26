/* NFSv4.1 client for Windows
 * Copyright (C) 2012 The Regents of the University of Michigan
 * Copyright (C) 2023-2024 Roland Mainz <roland.mainz@nrubsig.org>
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


BOOLEAN isFilenameTooLong(
    PUNICODE_STRING name,
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext)
{
    NFS41_FILE_FS_ATTRIBUTE_INFORMATION *attrs = &pVNetRootContext->FsAttrs;
    LONG len = attrs->MaximumComponentNameLength, count = 1, i;
    PWCH p = name->Buffer;
    for (i = 0; i < name->Length / 2; i++) {
        if (p[0] == L'\\') count = 1;
        else {
            if (p[0] == L'\0') return FALSE;
            if (count > len) return TRUE;
            count++;
        }
        p++;
    }
    return FALSE;
}

BOOLEAN isStream(
    PUNICODE_STRING name)
{
    LONG i;
    PWCH p = name->Buffer;
    for (i = 0; i < name->Length / 2; i++) {
        if (p[0] == L':') return TRUE;
        else if (p[0] == L'\0') return FALSE;
        p++;
    }
    return FALSE;
}

BOOLEAN is_root_directory(
    PRX_CONTEXT RxContext)
{
    __notnull PV_NET_ROOT VNetRoot = (PV_NET_ROOT)
        RxContext->pRelevantSrvOpen->pVNetRoot;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(RxContext->pRelevantSrvOpen->pVNetRoot);

    /* calculate the root directory's length, including vnetroot prefix,
     * mount path, and a trailing \ */
    const USHORT RootPathLen = VNetRoot->PrefixEntry.Prefix.Length +
            pVNetRootContext->MntPt.Length + sizeof(WCHAR);

    return RxContext->CurrentIrpSp->FileObject->FileName.Length <= RootPathLen;
}
