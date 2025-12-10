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

#ifndef NFS41SYS_DEBUG_H
#define NFS41SYS_DEBUG_H 1

typedef enum _nfs41_opcodes nfs41_opcodes;

#define _DRIVER_NAME_ "NFS4.1 Driver"

#ifdef _MSC_VER
ULONG DbgP(_In_z_ _Printf_format_string_ const char *restrict fmt, ...);
ULONG print_error(_In_z_ _Printf_format_string_ const char *restrict fmt, ...);
#else
ULONG DbgP(const char *restrict fmt, ...);
ULONG print_error(const char *restrict fmt, ...);
#endif /* _MSC_VER */
VOID print_fo_all(int on, IN PRX_CONTEXT c);
VOID print_srv_call(IN PMRX_SRV_CALL p);
VOID print_net_root(IN PMRX_NET_ROOT p);
VOID print_v_net_root(IN PMRX_V_NET_ROOT p);
VOID print_fcb(int on, IN PMRX_FCB p);
VOID print_srv_open(int on, IN PMRX_SRV_OPEN p);
VOID print_fobx(int on, IN PMRX_FOBX p);
VOID print_irp_flags(int on, PIRP irp);
VOID print_irps_flags(int on, PIO_STACK_LOCATION irps);
void print_nt_create_params(int on, NT_CREATE_PARAMETERS params);
const char *print_file_information_class(int InfoClass);
const char *print_fs_information_class(int InfoClass);
void print_hexbuf(const char *title, unsigned char *buf, int len);
void print_ioctl(int op);
void print_fs_ioctl(int op);
void print_driver_state(int state);
void print_file_object(int on, PFILE_OBJECT file);
void print_basic_info(int on, PFILE_BASIC_INFORMATION info);
void print_std_info(int on, PFILE_STANDARD_INFORMATION info);
void print_ea_info(PFILE_FULL_EA_INFORMATION info);
void print_get_ea(int on, PFILE_GET_EA_INFORMATION info);
void print_caching_level(int on, ULONG flag, PUNICODE_STRING s);
const char *opcode2string(nfs41_opcodes opcode);
void print_open_error(int on, int status);
void print_wait_status(int on, const char *str, NTSTATUS status,
                       const char *opcode, PVOID entry, LONGLONG xid);
void print_acl_args(SECURITY_INFORMATION info);
const char *fsctl2string(ULONG fsctl);
const char *reparsetag2string(ULONG tag);
#ifdef USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM
void print_lookasidelist_stat(const char *label, PNPAGED_LOOKASIDE_LIST ll);
#endif /* USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM */
void print_debug_header(PRX_CONTEXT RxContext);
void debug_printirpecps(PIRP irp);

#define PTR2PTRDIFF_T(p) (((char *)(p))-((char *)0))
#define PsGetCurrentProcessShortDebugId() ((int)PTR2PTRDIFF_T(PsGetCurrentProcessId()))

#ifdef NDEBUG
#define DbgEn()
#define DbgEx()
#define DbgR()
#else
#define DbgEn() DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, \
        "--> [%s] [%04x] %s\n", _DRIVER_NAME_, PsGetCurrentProcessShortDebugId(), \
        __func__); __try {

#define DbgEx() DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, \
        "<-- [%s] [%04x] %s status=0x%lx\n", _DRIVER_NAME_, PsGetCurrentProcessShortDebugId(), \
        __func__, (long)status); \
        } __except (EXCEPTION_EXECUTE_HANDLER) { \
            status = GetExceptionCode() ; \
            DbgP("Exception encountered with value = 0x%lx\n", (long)status); \
        }
#define DbgR() DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, \
        "<-- [%s] [%04x] %s\n", _DRIVER_NAME_, PsGetCurrentProcessShortDebugId(), __func__); \
        } __except (EXCEPTION_EXECUTE_HANDLER) { \
            NTSTATUS exc_status; \
            exc_status = GetExceptionCode() ; \
            DbgP("Exception encountered with value = 0x%lx\n", (long)exc_status); \
        }
#endif /* NDEBUG */

/* These are for ToasterDebugPrint */

#define DBG_ERROR    0x00000001
#define DBG_WARN     0x00000002
#define DBG_TRACE    0x00000004
#define DBG_INFO     0x00000008
#define DBG_DISP_IN  0x00000010 /* Marks entry into dispatch functions */
#define DBG_DISP_OUT 0x00000020 /* Marks exit from dispatch functions */

/* I want to do:
 * #define dprintk(flags, args...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_MASK | flags, ## args)
 * but the ... is gcc specific, can't seem to do it here.
 */
#define PNFS_TRACE_TAG      "PNFSMRX: "
#define PNFS_FLTR_ID        DPFLTR_IHVDRIVER_ID

#define DbgEnter() \
    DbgPrintEx(PNFS_FLTR_ID, DPFLTR_MASK | DBG_DISP_IN, "%s*** %s ***\n", \
        PNFS_TRACE_TAG, __func__);
#define DbgExit(status) \
    DbgPrintEx(PNFS_FLTR_ID, DPFLTR_MASK | DBG_DISP_OUT, "%s<-- %s <-- 0x%08lx\n", \
        PNFS_TRACE_TAG, __func__, (status));

ULONG
dprintk(
    IN PCHAR func,
    IN ULONG flags,
    IN PCHAR format,
    ...);

#endif /* !NFS41SYS_DEBUG_H */
