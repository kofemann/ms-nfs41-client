
/*
 * MIT License
 *
 * Copyright (c) 2024-2025 Roland Mainz <roland.mainz@nrubsig.org>
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
 * winsg.c - run Win32 or Cygwin program with a different (primary) group
 *
 * Written by Roland Mainz <roland.mainz@nrubsig.org>
 */

/*
 * Compile with:
 * $ clang -target x86_64-pc-windows-gnu -municode -Wall -Wextra \
 *      -DUNICODE=1 -D_UNICODE=1 -g winsg.c -o winsg.x86_64.exe #
 */

#define UNICODE 1
#define _UNICODE 1

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <locale.h>
#include <fcntl.h>
#include <assert.h>
#include <Lmcons.h>
#include <process.h>

#if 0
#define D(x) x
#else
#define D(x)
#endif

#ifdef _WIN64
#define CYGWIN_BASH_PATH L"C:\\cygwin64\\bin\\bash.exe"
#else
#define CYGWIN_BASH_PATH L"C:\\cygwin\\bin\\bash.exe"
#endif /* _WIN64 */
#define WIN32_CMDEXE_PATH L"C:\\Windows\\system32\\cmd.exe"
#define WIN32_POWERSHELLEXE_PATH \
    L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

/*
 * DECLARE_SID_BUFFER - declare a buffer for a SID value
 * Note that buffers with SID values must be 16byte aligned
 * on Windows 10/32bit, othewise the kernel might return
 * |ERROR_NOACCESS|(=998) - "Invalid access to memory location".
 */
#ifdef _MSC_BUILD
/* Visual Studio */
#define DECLARE_SID_BUFFER(varname) \
    __declspec(align(16)) char (varname)[SECURITY_MAX_SID_SIZE+1]
#else
/* clang */
#define DECLARE_SID_BUFFER(varname) \
    char (varname)[SECURITY_MAX_SID_SIZE+1] __attribute__((aligned(16)))
#endif /* _MSC_BUILD */

/*
 * Performance hack:
 * GETTOKINFO_EXTRA_BUFFER - extra space for more data
 * |GetTokenInformation()| for |TOKEN_USER| and |TOKEN_PRIMARY_GROUP|
 * always fails in Win10 with |ERROR_INSUFFICIENT_BUFFER| if you
 * just pass the |sizeof(TOKEN_*)| value. Instead of calling
 * |GetTokenInformation()| with |NULL| arg to obtain the size to
 * allocate we just provide 8192 bytes of extra space after the
 * |TOKEN_*| size, and pray it is enough
 */
#define GETTOKINFO_EXTRA_BUFFER (8192)

D(
static
bool get_token_primarygroup_name(HANDLE tok, wchar_t *out_buffer)
{
    DWORD tokdatalen;
    PTOKEN_PRIMARY_GROUP ptpgroup;
    PSID pgsid;
    DWORD namesize = GNLEN+1;
    wchar_t domainbuffer[UNLEN+1];
    DWORD domainbuffer_size = sizeof(domainbuffer);
    SID_NAME_USE name_use;

    tokdatalen = sizeof(TOKEN_PRIMARY_GROUP)+GETTOKINFO_EXTRA_BUFFER;
    ptpgroup = _alloca(tokdatalen);
    if (!GetTokenInformation(tok, TokenPrimaryGroup, ptpgroup,
        tokdatalen, &tokdatalen)) {
        D((void)fwprintf(stderr, L"get_token_primarygroup_name: "
            L"GetTokenInformation(tok=0x%p, TokenPrimaryGroup) failed, "
            L"status=%d.\n",
            (void *)tok, (int)GetLastError()));
        return false;
    }

    pgsid = ptpgroup->PrimaryGroup;

    if (!LookupAccountSidW(NULL, pgsid, out_buffer, &namesize,
        domainbuffer, &domainbuffer_size, &name_use)) {
        D((void)fwprintf(stderr, L"get_token_primarygroup_name: "
            L"LookupAccountSidW() failed, status=%d.\n",
            (int)GetLastError()));
        return false;
    }

    return true;
}
)

static
bool is_group_in_token(HANDLE tok, PSID qsid)
{
    DWORD tokdatalen;
    PTOKEN_GROUPS ptgroups;

    tokdatalen = sizeof(TOKEN_GROUPS)+GETTOKINFO_EXTRA_BUFFER;
    ptgroups = _alloca(tokdatalen);
    if (!GetTokenInformation(tok, TokenGroups, ptgroups,
        tokdatalen, &tokdatalen)) {
        D((void)fwprintf(stderr, L"is_group_in_token: "
            L"GetTokenInformation(tok=0x%p, TokenGroups) failed, "
            L"status=%d.\n",
            (void *)tok, (int)GetLastError()));
        return false;
    }

    DWORD i;
    D(
        (void)fwprintf(stderr, L"is_group_in_token: got %d groups\n",
            (int)ptgroups->GroupCount)
    );
    for (i = 0 ; i < ptgroups->GroupCount ; i++) {
        if (EqualSid(qsid, ptgroups->Groups[i].Sid) &&
            (ptgroups->Groups[i].Attributes & SE_GROUP_ENABLED)) {
            D((void)fwprintf(stdout, L"is_group_in_token: #match\n"));
            return true;
        }
    }

    D((void)fwprintf(stdout, L"is_group_in_token: #no match\n"));

    return false;
}

static
int print_groups_in_token(HANDLE tok)
{
    DWORD tokdatalen;
    PTOKEN_GROUPS ptgroups;
    wchar_t namebuffer[GNLEN+1];
    DWORD namesize;
    wchar_t domainbuffer[UNLEN+1];
    DWORD domainbuffer_size;
    SID_NAME_USE name_use;

    tokdatalen = sizeof(TOKEN_GROUPS)+GETTOKINFO_EXTRA_BUFFER;
    ptgroups = _alloca(tokdatalen);
    if (!GetTokenInformation(tok, TokenGroups, ptgroups,
        tokdatalen, &tokdatalen)) {
        D((void)fwprintf(stderr, L"print_groups_in_token: "
            L"GetTokenInformation(tok=0x%p, TokenGroups) failed, "
            L"status=%d.\n",
            (void *)tok, (int)GetLastError()));
        return 1;
    }

    DWORD i;
    D(
        (void)fwprintf(stderr, L"print_groups_in_token: got %d groups\n",
            (int)ptgroups->GroupCount)
    );
    for (i = 0 ; i < ptgroups->GroupCount ; i++) {
        if (!(ptgroups->Groups[i].Attributes & SE_GROUP_ENABLED)) {
            continue;
        }

        namesize = sizeof(namebuffer)-1;
        domainbuffer_size = sizeof(domainbuffer)-1;

        if (!LookupAccountSidW(NULL, ptgroups->Groups[i].Sid,
            namebuffer, &namesize, domainbuffer, &domainbuffer_size, &name_use)) {
            D((void)fwprintf(stderr, L"print_groups_in_token: "
                L"LookupAccountSidW() failed, status=%d.\n",
                (int)GetLastError()));
            continue;
        }

        (void)fwprintf(stdout, L"group='%ls'\n", namebuffer);
    }

    D((void)fwprintf(stdout, L"is_group_in_token: #no match\n"));

    return 0;
}

static
bool get_group_sid(const wchar_t *groupname, PSID pgsid, PDWORD pgsid_size)
{
    wchar_t domainbuffer[UNLEN+1];
    DWORD domainbuffer_size = sizeof(domainbuffer);
    SID_NAME_USE name_use;

    if (!LookupAccountNameW(NULL, groupname,
        pgsid, pgsid_size, domainbuffer, &domainbuffer_size, &name_use)) {
        D((void)fwprintf(stderr, L"get_group_sid: "
            L"LookupAccountNameW() failed.\n"));
        return false;
    }

    return true;
}

static
bool set_token_primarygroup_sid(HANDLE tok, PSID pgsid)
{
    DWORD tokdatalen;
    TOKEN_PRIMARY_GROUP tpgroup;

    tokdatalen = sizeof(TOKEN_PRIMARY_GROUP);
    tpgroup.PrimaryGroup = pgsid;
    if (!SetTokenInformation(tok, TokenPrimaryGroup,
        &tpgroup, tokdatalen)) {
        D((void)fwprintf(stderr, L"set_token_primarygroup_sid: "
            L"SetTokenInformation(tok=0x%p, TokenPrimaryGroup) failed, "
            L"status=%d\n",
            (void *)tok, (int)GetLastError()));
        return false;
    }

    return true;
}

static
wchar_t *wcpcpy(wchar_t *restrict s1, const wchar_t *restrict s2)
{
    size_t l = wcslen(s2);
    return memcpy(s1, s2, (l+1)*sizeof(wchar_t)) + l*sizeof(wchar_t);
}

static
void win32cmd_quotearg(wchar_t *s1, const wchar_t *s2)
{
    wchar_t c;

    *s1++ = L'"';
    while ((c = *s2) != L'\0') {
        switch(c) {
            case L'"':
                *s1++=L'\\';
                *s1 = c;
                break;
            default:
                *s1 = c;
                break;
        }
        s1++;
        s2++;
    }
    *s1++ = L'"';
    *s1 = L'\0';
}

static
int usage(void)
{
    (void)fwprintf(stderr,
        L"Usage: winsg [-] -g group [-c command]\n"
        L"Usage: winsg [-] /g group [/C command]\n"
        L"Usage: winsg [-] /g group [/P command]\n"
        L"Usage: winsg -L\n"
        L"Usage: winsg /? | -h | --help\n"
        L"Execute command as different primary group ID\n"
        L"\n"
        L"Examples:\n"
        L"\t1. Run new cmd.exe with primary group 'abc1':\n"
        L"\t\twinsg /g abc1 /C\n"
        L"\n"
        L"\t2. Run new powershell.exe with primary group 'abc1':\n"
        L"\t\twinsg /p abc1 /P\n"
        L"\n"
        L"\t3. Run new Cygwin shell (bash) with primary group 'abc2':\n"
        L"\t\twinsg -g abc2 -c\n"
        L"\n"
        L"\t4. Start /bin/id from cmd.exe with primary group 'abc3':\n"
        L"\t\twinsg /g abc3 /C 'C:\\cygwin64\\bin\\id.exe -a'\n"
        L"\n"
        L"\t5. Start /bin/id from powershell.exe with primary group 'abc3':\n"
        L"\t\twinsg /g abc3 /P 'C:\\cygwin64\\bin\\id.exe -a'\n"
        L"\n"
        L"\t6. Start /bin/id from Cygwin shell (bash) with primary "
            L"group 'abc4':\n"
        L"\t\twinsg -g abc4 -c '/bin/id.exe -a'\n"
        L"\n"
        L"\t7. List currently available groups which can be passed to "
            L"winsg -g ...\n"
        L"\t\twinsg -L\n"
        L"\n"
        L"Please report bugs to "
        L"Roland Mainz <roland.mainz@nrubsig.org>.\n");

    return 2;
}


enum shelltype {
    SHELLTYPE_NOT_SET = 0,
    SHELLTYPE_NONE,
    SHELLTYPE_CMD,
    SHELLTYPE_SYSTEM,
    SHELLTYPE_POWERSHELL
};

int wmain(int ac, wchar_t *av[])
{
    enum shelltype st = SHELLTYPE_NOT_SET;
    int cmd_arg_index = -1;
    const wchar_t *newgrpname = NULL;
    HANDLE tok = INVALID_HANDLE_VALUE;
    int subcmdret = EXIT_FAILURE;
    int retval = 1;
    int i;
    bool cmd_runasgroup = false;
    bool cmd_list_token = false;

    (void)setlocale(LC_CTYPE, ".UTF-8");

    (void)_setmode(fileno(stdin), _O_U8TEXT);
    (void)_setmode(fileno(stdout), _O_U8TEXT);
    (void)_setmode(fileno(stderr), _O_U8TEXT);

    for (i=1 ; i < ac ; i++) {
        D((void)fwprintf(stderr, L"# i=%d, av[i]='%ls'\n", i, av[i]));

        if (!wcscmp(av[i], L"-")) {
            (void)fwprintf(stderr,
                L"%ls: Run in new login not supported yet.\n", av[0]);
            retval = 1;
            goto done;
        }
        else if (!wcscmp(av[i], L"-c")) {
            /* -c can take zero or one argument */
            if ((ac-i) > 2) {
                (void)fwprintf(stderr,
                    L"%ls: Too many arguments for -c.\n", av[0]);
                retval = 1;
                goto done;
            }

            cmd_runasgroup = true;
            st = SHELLTYPE_SYSTEM;
            cmd_arg_index = i+1;
            break;
        }
        else if (!wcscmp(av[i], L"/C")) {
            /* /C can take zero or one argument */
            if ((ac-i) > 2) {
                (void)fwprintf(stderr,
                    L"%ls: Too many arguments for /C.\n", av[0]);
                retval = 1;
                goto done;
            }

            cmd_runasgroup = true;
            st = SHELLTYPE_CMD;
            cmd_arg_index = i+1;
            break;
        }
        else if (!wcscmp(av[i], L"/P")) {
            /* /P can take zero or one argument */
            if ((ac-i) > 2) {
                (void)fwprintf(stderr,
                    L"%ls: Too many arguments for /P.\n", av[0]);
                retval = 1;
                goto done;
            }

            cmd_runasgroup = true;
            st = SHELLTYPE_POWERSHELL;
            cmd_arg_index = i+1;
            break;
        }
        else if ((!wcscmp(av[i], L"-g")) ||
            (!wcscmp(av[i], L"/g"))) {
            newgrpname = av[i+1];
            i++;
            cmd_runasgroup = true;
        }
        else if ((!wcscmp(av[i], L"/?")) ||
                (!wcscmp(av[i], L"-h")) ||
                (!wcscmp(av[i], L"--help")) ||
                (!wcscmp(av[i], L"--usage"))) {
            retval = usage();
            goto done;
        }
        else if (!wcscmp(av[i], L"-L")) {
            cmd_list_token = true;
        }
        else if ((av[i][0] == L'-') || (av[i][0] == L'/')) {
            (void)fwprintf(stderr,
                L"%ls: Unsupported option '%ls'.\n", av[0], av[i]);
            retval = usage();
            goto done;
        }
        else {
            if ((i == 1) && (*av[i] != L'-')) {
                cmd_runasgroup = true;
                newgrpname = av[i];
                continue;
            }

            cmd_runasgroup = true;
            cmd_arg_index = i+1;
            st = SHELLTYPE_NONE;
            break;
        }
    }

    if (((int)cmd_runasgroup+(int)cmd_list_token) > 1) {
        (void)fwprintf(stderr, L"%ls: Incompatible option combination\n",
            av[0]);
        retval = 1;
        goto done;
    }

    /*
     * Handle newgrp(1)-like behaviour (run new shell (in our
     * case cmd.exe) with requested group), e.g. ...
     * $ winsg -g cygwingrp1
     * $ winsg cygwingrp1
     */
    if (cmd_runasgroup &&
        (st == SHELLTYPE_NOT_SET) && (cmd_arg_index == -1)) {
        st = SHELLTYPE_NONE;
        /* set |cmd_arg_index| to the end of |av|, which is |NULL| */
        cmd_arg_index = i;
    }

    if ((!cmd_list_token) && (!newgrpname)) {
        (void)fwprintf(stderr, L"%ls: No group name given.\n", av[0]);
        retval = 1;
        goto done;
    }

    D((void)fwprintf(stderr,
        L"# shelltype=%d, cmd_arg_index=%d, "
        L"av[cmd_arg_index]='%ls', "
        L"new group name '%ls'\n",
        (int)st,
        cmd_arg_index,
        ((cmd_arg_index >= 0)?av[cmd_arg_index]:L"<negative-av-idx>"),
        newgrpname));

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_QUERY|TOKEN_ADJUST_DEFAULT|TOKEN_DUPLICATE,
        &tok)) {
        (void)fwprintf(stderr, L"%ls: Cannot open token.\n", av[0]);
        retval = 1;
        goto done;
    }

    if (cmd_list_token) {
        retval = print_groups_in_token(tok);
        goto done;
    }

    D(
        wchar_t pgroupname[GNLEN+1];

        get_token_primarygroup_name(tok, pgroupname);
        (void)fwprintf(stdout, L"primary group name '%ls'\n", pgroupname);
    )

    DECLARE_SID_BUFFER(sidbuff);
    PSID pgsid = (PSID)sidbuff;
    DWORD pgsid_size = SECURITY_MAX_SID_SIZE;

    if (!get_group_sid(newgrpname, pgsid, &pgsid_size)) {
        (void)fwprintf(stderr, L"%ls: Could not find group '%ls'.\n",
            av[0], newgrpname);
        retval = 1;
        goto done;
    }

    if (!is_group_in_token(tok, pgsid)) {
        (void)fwprintf(stderr,
            L"%ls: Current user is not a member of group '%ls'.\n",
            av[0], newgrpname);
        retval = 1;
        goto done;
    }

    if (!set_token_primarygroup_sid(tok, pgsid)) {
        (void)fwprintf(stderr,
            L"%ls: Could not switch to new primary group '%ls'.\n",
            av[0], newgrpname);
        retval = 1;
        goto done;
    }

    D(
        get_token_primarygroup_name(tok, pgroupname);
        (void)fwprintf(stdout, L"primary group name '%ls'\n", pgroupname);
    )

    (void)_flushall();

    retval = 0;

    switch(st) {
        case SHELLTYPE_SYSTEM:
            if (av[cmd_arg_index] != NULL) {
                size_t cmdbuff_size = wcslen(CYGWIN_BASH_PATH)*sizeof(wchar_t)+
                    16*sizeof(wchar_t)+
                    wcslen(av[cmd_arg_index])*sizeof(wchar_t)*2;
                wchar_t *cmdbuff = alloca(cmdbuff_size);
                wchar_t *s = cmdbuff;
                s = wcpcpy(s, CYGWIN_BASH_PATH);
                s = wcpcpy(s, L" -c ");

                win32cmd_quotearg(s, av[cmd_arg_index]);
                D((void)fwprintf(stderr, L"# executing '%ls'\n", cmdbuff));
                subcmdret = _wsystem(cmdbuff);
            }
            else {
                subcmdret = _wsystem(CYGWIN_BASH_PATH);
            }
            break;
        case SHELLTYPE_CMD:
            if (av[cmd_arg_index] != NULL) {
                subcmdret = _wspawnl(_P_WAIT,
                    WIN32_CMDEXE_PATH, WIN32_CMDEXE_PATH,
                    L"/C", av[cmd_arg_index], NULL);
            }
            else {
                subcmdret = _wspawnl(_P_WAIT,
                    WIN32_CMDEXE_PATH, WIN32_CMDEXE_PATH, NULL);
            }
            break;
        case SHELLTYPE_POWERSHELL:
            if (av[cmd_arg_index] != NULL) {
                subcmdret = _wspawnl(_P_WAIT,
                    WIN32_POWERSHELLEXE_PATH, WIN32_POWERSHELLEXE_PATH,
                    L"-Command", av[cmd_arg_index], NULL);
            }
            else {
                subcmdret = _wspawnl(_P_WAIT,
                    WIN32_POWERSHELLEXE_PATH, WIN32_POWERSHELLEXE_PATH, NULL);
            }
            break;
        case SHELLTYPE_NONE:
            subcmdret = _wspawnl(_P_WAIT,
                WIN32_CMDEXE_PATH, WIN32_CMDEXE_PATH, NULL);
            break;
        default:
            assert(0);
            break;
    }

    D((void)fwprintf(stdout, L"#mark winsg done, subcmdret=%d\n",
        (int)subcmdret));

done:
    if (tok != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(tok);
    }

    return retval;
}
