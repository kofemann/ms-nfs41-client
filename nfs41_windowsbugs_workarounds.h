/* NFSv4.1 client for Windows
 * Copyright (C) 2025-2026 Roland Mainz <roland.mainz@nrubsig.org>
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


#ifndef _NFS41_DRIVER_WINDOWSBUGS_WORKAROUNDS_
#define _NFS41_DRIVER_WINDOWSBUGS_WORKAROUNDS_ 1

/*
 * WINDOWSBUG_WORKAROUND_* - enable/disable workarounds for Windows bugs
 * we encountered
 */

/*
 * |WINDOWSBUG_WORKAROUND_RTLUTF8STRINGTOUNICODESTRING_READS_BEYOND_BUFFER| -
 * workaround for the bug that |RtlUTF8StringToUnicodeString()| reads more
 * bytes (likely up to |sizeof(void *)|) than the maximum size of the input
 * buffer, which can cause crashes when running with Windows verifer active
 * (e.g with $ /cygdrive/c/Windows/system32/verifier /flags 0x6019 /driver
 * nfs41_driver.sys #) like this:
 * ---- snip ----
 * STACK_TEXT:
 * nt!KeBugCheckEx
 * nt!MiSystemFault+0x1b70a3
 * nt!MmAccessFault+0x400
 * nt!KiPageFault+0x36d
 * nt!CountUTF8ToUnicode+0xc2
 * nt!RtlUTF8StringToUnicodeString+0x31
 * nfs41_driver!unmarshal_nfs41_setattr+0x114 [C:\cygwin64\home\roland_mainz\work\msnfs41_uidmapping\ms-nfs41-client\sys\nfs41sys_setfileinfo.c @ 200]
 * nfs41_driver!nfs41_downcall+0x546 [C:\cygwin64\home\roland_mainz\work\msnfs41_uidmapping\ms-nfs41-client\sys\nfs41sys_updowncall.c @ 802]
 * nfs41_driver!nfs41_DevFcbXXXControlFile+0x121 [C:\cygwin64\home\roland_mainz\work\msnfs41_uidmapping\ms-nfs41-client\sys\nfs41sys_driver.c @ 747]
 * nfs41_driver!RxXXXControlFileCallthru+0x76 [base\fs\rdr2\rdbss\ntdevfcb.c @ 130]
 * nfs41_driver!RxCommonDevFCBIoCtl+0x58 [base\fs\rdr2\rdbss\ntdevfcb.c @ 491]
 * nfs41_driver!RxFsdCommonDispatch+0x442 [base\fs\rdr2\rdbss\ntfsd.c @ 848]
 * nfs41_driver!RxFsdDispatch+0xfd [base\fs\rdr2\rdbss\ntfsd.c @ 442]
 * nfs41_driver!nfs41_FsdDispatch+0x67 [C:\cygwin64\home\roland_mainz\work\msnfs41_uidmapping\ms-nfs41-client\sys\nfs41sys_driver.c @ 1250]
 * nt!IopfCallDriver+0x53
 * nt!IovCallDriver+0x266
 * nt!IofCallDriver+0x188f09
 * mup!MupiCallUncProvider+0xb3
 * mup!MupStateMachine+0x59
 * mup!MupFsdIrpPassThrough+0x17e
 * nt!IopfCallDriver+0x53
 * nt!IovCallDriver+0x266
 * nt!IofCallDriver+0x188f09
 * FLTMGR!FltpDispatch+0xd1
 * nt!IopfCallDriver+0x53
 * nt!IovCallDriver+0x266
 * nt!IofCallDriver+0x188f09
 * nt!IopSynchronousServiceTail+0x361
 * nt!IopXxxControlFile+0xd0a
 * nt!NtDeviceIoControlFile+0x56
 * nt!KiSystemServiceCopyEnd+0x25
 * ntdll!NtDeviceIoControlFile+0x14
 * KERNELBASE!DeviceIoControl+0x6b
 * KERNEL32!DeviceIoControlImplementation+0x81
 * nfsd!nfsd_worker_thread_main+0x392 [C:\cygwin64\home\roland_mainz\work\msnfs41_uidmapping\ms-nfs41-client\daemon\nfs41_daemon.c @ 258]
 * nfsd!nfsd_thread_main+0x1f [C:\cygwin64\home\roland_mainz\work\msnfs41_uidmapping\ms-nfs41-client\daemon\nfs41_daemon.c @ 279]
 * ucrtbased!invoke_thread_procedure+0x2c [d:\th\minkernel\crts\ucrt\src\appcrt\startup\thread.cpp @ 92]
 * ucrtbased!thread_start<unsigned int (__cdecl*)(void * __ptr64)>+0x93 [d:\th\minkernel\crts\ucrt\src\appcrt\startup\thread.cpp @ 115]
 * KERNEL32!BaseThreadInitThunk+0x14
 * ntdll!RtlUserThreadStart+0x21
 * ---- snip ----
 */
#define WINDOWSBUG_WORKAROUND_RTLUTF8STRINGTOUNICODESTRING_READS_BEYOND_BUFFER 1


/*
 * |WINDOWSBUG_WORKAROUND_LOWIO_OP_UNLOCK_HAS_RANDOM_VALUE_IN_LOWIO_LOCK_LIST| -
 * workaround for uninitialised var issues:
 * 1. For |LOWIO_OP_UNLOCK_MULTIPLE| |lock->ExclusiveLock| has
 *   random(uninitialised var ?)
 * 2. For |LOWIO_OP_UNLOCK| |lock->ExclusiveLock| is always |0|
 *
 * As workaround for both [1] and [2] we always set the value
 * to |TRUE| for now.
 * This only works because |nfs41_unlock()| states:
 * ---- snip ----
 * https://datatracker.ietf.org/doc/html/rfc5661 Section 18.12.3 says:
 * "... the server MUST accept any legal value for locktype ..."
 * ---- snip ----
 */
#define WINDOWSBUG_WORKAROUND_LOWIO_OP_UNLOCK_HAS_RANDOM_VALUE_IN_LOWIO_LOCK_LIST 1


/*
 * |WINDOWSBUG_WORKAROUND_GETADDRINFOEXA_STOPS_IMPERSONATION| - Windows
 * bug: |GetAddrInfoExA()| ends impersonation
 * Tested on CYGWIN_NT-10.0-19045 3.6.0-0.115.g579064bf4d40.x86
 */
#define WINDOWSBUG_WORKAROUND_GETADDRINFOEXA_STOPS_IMPERSONATION 1


/*
 * |WINDOWSBUG_WORKAROUND_WS2TCPIP_H| - BUG: WS2tcpip.h somenow maps
 * |FreeAddrInfoExA()| to use the wide-char version
 */
#define WINDOWSBUG_WORKAROUND_WS2TCPIP_H 1

/*
 * |WINDOWSBUG_WORKAROUND_EXPLORER_BIGVOLUMELABEL_CRASH| - Windows bug:
 * Windows Explorer can only handle up to 31 characters per label,
 * otherwise the info field can have "blank"/empty fields, or Explorer
 * crashes
 */
#define WINDOWSBUG_WORKAROUND_EXPLORER_BIGVOLUMELABEL_CRASH 1

#endif /* !_NFS41_DRIVER_WINDOWSBUGS_WORKAROUNDS_ */
