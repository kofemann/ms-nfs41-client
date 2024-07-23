
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

/*
 * winsg.c - run Win32 or Cygwin program with a different (primary) group
 *
 * Written by Roland Mainz <roland.mainz@nrubsig.org>
 */

/*
 * Compile with:
 * $ clang -target x86_64-pc-windows-gnu -Wall -g winsg.c -o winsg.exe #
 */

#define UNICODE 1
#define _UNICODE 1

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <Lmcons.h>
#include <process.h>

#if 0
#define D(x) x
#else
#define D(x)
#endif

#ifdef _WIN64
#define CYGWIN_BASH_PATH "C:\\cygwin64\\bin\\bash.exe"
#else
#define CYGWIN_BASH_PATH "C:\\cygwin\\bin\\bash.exe"
#endif /* _WIN64 */
#define WIN32_CMDEXE_PATH "C:\\Windows\\system32\\cmd.exe"

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
bool get_token_primarygroup_name(HANDLE tok, char *out_buffer)
{
    DWORD tokdatalen;
    PTOKEN_PRIMARY_GROUP ptpgroup;
    PSID pgsid;
    DWORD namesize = GNLEN+1;
    char domainbuffer[UNLEN+1];
    DWORD domainbuffer_size = sizeof(domainbuffer);
    SID_NAME_USE name_use;

    tokdatalen = sizeof(TOKEN_PRIMARY_GROUP)+GETTOKINFO_EXTRA_BUFFER;
    ptpgroup = _alloca(tokdatalen);
    if (!GetTokenInformation(tok, TokenPrimaryGroup, ptpgroup,
        tokdatalen, &tokdatalen)) {
        D((void)fprintf(stderr, "get_token_primarygroup_name: "
            "GetTokenInformation(tok=0x%p, TokenPrimaryGroup) failed, "
            "status=%d.\n",
            (void *)tok, (int)GetLastError()));
        return false;
    }

    pgsid = ptpgroup->PrimaryGroup;

    if (!LookupAccountSidA(NULL, pgsid, out_buffer, &namesize,
        domainbuffer, &domainbuffer_size, &name_use)) {
        D((void)fprintf(stderr, "get_token_primarygroup_name: "
            "LookupAccountSidA() failed, status=%d.\n",
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
        D((void)fprintf(stderr, "is_group_in_token: "
            "GetTokenInformation(tok=0x%p, TokenGroups) failed, "
            "status=%d.\n",
            (void *)tok, (int)GetLastError()));
        return false;
    }

    int i;
    D(
        (void)fprintf(stderr, "is_group_in_token: got %d groups\n",
            (int)ptgroups->GroupCount)
    );
    for (i = 0 ; i < ptgroups->GroupCount ; i++) {
        if (EqualSid(qsid, ptgroups->Groups[i].Sid) &&
            (ptgroups->Groups[i].Attributes & SE_GROUP_ENABLED)) {
            D((void)puts("is_group_in_token: #match"));
            return true;
        }
    }

    D((void)puts("is_group_in_token: #no match"));

    return false;
}

static
int print_groups_in_token(HANDLE tok)
{
    DWORD tokdatalen;
    PTOKEN_GROUPS ptgroups;
    char namebuffer[GNLEN+1];
    DWORD namesize = GNLEN+1;
    char domainbuffer[UNLEN+1];
    DWORD domainbuffer_size = sizeof(domainbuffer);
    SID_NAME_USE name_use;

    tokdatalen = sizeof(TOKEN_GROUPS)+GETTOKINFO_EXTRA_BUFFER;
    ptgroups = _alloca(tokdatalen);
    if (!GetTokenInformation(tok, TokenGroups, ptgroups,
        tokdatalen, &tokdatalen)) {
        D((void)fprintf(stderr, "print_groups_in_token: "
            "GetTokenInformation(tok=0x%p, TokenGroups) failed, "
            "status=%d.\n",
            (void *)tok, (int)GetLastError()));
        return 1;
    }

    int i;
    D(
        (void)fprintf(stderr, "print_groups_in_token: got %d groups\n",
            (int)ptgroups->GroupCount)
    );
    for (i = 0 ; i < ptgroups->GroupCount ; i++) {
        if (!(ptgroups->Groups[i].Attributes & SE_GROUP_ENABLED)) {
            continue;
        }

        if (!LookupAccountSidA(NULL, ptgroups->Groups[i].Sid,
            namebuffer, &namesize, domainbuffer, &domainbuffer_size, &name_use)) {
            D((void)fprintf(stderr, "print_groups_in_token: "
                "LookupAccountSidA() failed, status=%d.\n",
                (int)GetLastError()));
            continue;
        }

        (void)printf("group='%s'\n", namebuffer);
    }

    D((void)puts("is_group_in_token: #no match"));

    return 0;
}

static
bool get_group_sid(const char *groupname, PSID pgsid, PDWORD pgsid_size)
{
    char domainbuffer[UNLEN+1];
    DWORD domainbuffer_size = sizeof(domainbuffer);
    SID_NAME_USE name_use;

    if (!LookupAccountNameA(NULL, groupname,
        pgsid, pgsid_size, domainbuffer, &domainbuffer_size, &name_use)) {
        D((void)fprintf(stderr, "get_group_sid: "
            "LookupAccountNameA() failed.\n"));
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
        D((void)fprintf(stderr, "set_token_primarygroup_sid: "
            "SetTokenInformation(tok=0x%p, TokenPrimaryGroup) failed, "
            "status=%d\n",
            (void *)tok, (int)GetLastError()));
        return false;
    }

    return true;
}

static
char *stpcpy (char *restrict s1, const char *restrict s2)
{
    size_t l = strlen(s2);
    return memcpy(s1, s2, l+1) + l;
}

static
void win32cmd_quotearg(char *s1, const char *s2)
{
    int c;
    *s1++ = '"';
    while ((c = *s2) != '\0') {
        switch(c) {
            case '"':
                *s1++='\\';
                *s1 = c;
                break;
            default:
                *s1 = c;
                break;
        }
        s1++;
        s2++;
    }
    *s1++ = '"';
    *s1 = '\0';
}

static
int usage(void)
{
    (void)fprintf(stderr,
        "Usage: winsg [-] -g group [-c command]\n"
        "Usage: winsg [-] /g group [/C command]\n"
        "Usage: winsg -L\n"
        "Usage: winsg /? | -h | --help\n"
        "Execute command as different primary group ID\n"
        "\n"
        "Examples:\n"
        "\t1. Run new cmd.exe with primary group 'abc1':\n"
        "\t\twinsg /g abc1 /C\n"
        "\n"
        "\t2. Run new Cygwin shell (bash) with primary group 'abc2':\n"
        "\t\twinsg -g abc2 -g\n"
        "\n"
        "\t3. Start /bin/id from cmd.exe with primary group 'abc3':\n"
        "\t\twinsg /g abc3 /C 'C:\\cygwin64\\bin\\id.exe -a'\n"
        "\n"
        "\t4. Start /bin/id from Cygwin shell (bash) with primary "
            "group 'abc4':\n"
        "\t\twinsg -g abc4 -c '/bin/id.exe -a'\n"
        "\n"
        "\t5. List currently available groups which can be passed to "
            "winsg -g ...\n"
        "\t\twinsg -L\n"
        "\n"
        "Please report bugs to "
        "Roland Mainz <roland.mainz@nrubsig.org>.\n");

    return 2;
}


enum shelltype {
    SHELLTYPE_NOT_SET = 0,
    SHELLTYPE_NONE,
    SHELLTYPE_CMD,
    SHELLTYPE_SYSTEM
};

int main(int ac, char *av[])
{
    enum shelltype st = SHELLTYPE_NOT_SET;
    int cmd_arg_index = -1;
    const char *newgrpname = NULL;
    HANDLE tok = INVALID_HANDLE_VALUE;
    int subcmdret = EXIT_FAILURE;
    int retval = 1;
    int i;
    bool cmd_runasgroup = false;
    bool cmd_list_token = false;

    for (i=1 ; i < ac ; i++) {
        D((void)fprintf(stderr, "# i=%d, av[i]='%s'\n", i, av[i]));

        if (!strcmp(av[i], "-")) {
            (void)fprintf(stderr, "%s: "
                "Run in new login not supported yet.\n", av[0]);
            retval = 1;
            goto done;
        }
        else if (!strcmp(av[i], "-c")) {
            /* -c can take zero or one argument */
            if ((ac-i) > 2) {
                (void)fprintf(stderr, "%s: "
                    "Too many arguments for -c.\n", av[0]);
                retval = 1;
                goto done;
            }

            cmd_runasgroup = true;
            st = SHELLTYPE_SYSTEM;
            cmd_arg_index = i+1;
            break;
        }
        else if (!strcmp(av[i], "/C")) {
            /* /C can take zero or one argument */
            if ((ac-i) > 2) {
                (void)fprintf(stderr, "%s: "
                    "Too many arguments for /C.\n", av[0]);
                retval = 1;
                goto done;
            }

            cmd_runasgroup = true;
            st = SHELLTYPE_CMD;
            cmd_arg_index = i+1;
            break;
        }
        else if ((!strcmp(av[i], "-g")) ||
            (!strcmp(av[i], "/g"))) {
            newgrpname = av[i+1];
            i++;
            cmd_runasgroup = true;
        }
        else if ((!strcmp(av[i], "/?")) ||
                (!strcmp(av[i], "-h")) ||
                (!strcmp(av[i], "--help")) ||
                (!strcmp(av[i], "--usage"))) {
            retval = usage();
            goto done;
        }
        else if (!strcmp(av[i], "-L")) {
            cmd_list_token = true;
        }
        else if ((av[i][0] == '-') || (av[i][0] == '/')) {
            (void)fprintf(stderr, "%s: "
                "Unsupported option '%s'.\n", av[0], av[i]);
            retval = usage();
            goto done;
        }
        else {
            if ((i == 1) && (*av[i] != '-')) {
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
        (void)fprintf(stderr, "%s: Incompatible option combination\n",
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
        (void)fprintf(stderr, "%s: No group name given.\n", av[0]);
        retval = 1;
        goto done;
    }

    D((void)fprintf(stderr,
        "# shelltype=%d, cmd_arg_index=%d, "
        "av[cmd_arg_index]='%s', "
        "new group name '%s'\n",
        (int)st, cmd_arg_index, av[cmd_arg_index], newgrpname));

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_QUERY|TOKEN_ADJUST_DEFAULT|TOKEN_DUPLICATE,
        &tok)) {
        (void)fprintf(stderr, "%s: Cannot open token.\n", av[0]);
        retval = 1;
        goto done;
    }

    if (cmd_list_token) {
        retval = print_groups_in_token(tok);
        goto done;
    }

    D(
        char pgroupname[GNLEN+1];

        get_token_primarygroup_name(tok, pgroupname);
        (void)printf("primary group name '%s'\n", pgroupname);
    )

    DECLARE_SID_BUFFER(sidbuff);
    PSID pgsid = (PSID)sidbuff;
    DWORD pgsid_size = SECURITY_MAX_SID_SIZE;

    if (!get_group_sid(newgrpname, pgsid, &pgsid_size)) {
        (void)fprintf(stderr, "%s: Could not find group '%s'.\n",
            av[0], newgrpname);
        retval = 1;
        goto done;
    }

    if (!is_group_in_token(tok, pgsid)) {
        (void)fprintf(stderr, "%s: "
            "Current user is not a member of group '%s'.\n",
            av[0], newgrpname);
        retval = 1;
        goto done;
    }

    if (!set_token_primarygroup_sid(tok, pgsid)) {
        (void)fprintf(stderr,
            "%s: Could not switch to new primary group '%s'.\n",
            av[0], newgrpname);
        retval = 1;
        goto done;
    }

    D(
        get_token_primarygroup_name(tok, pgroupname);
        (void)printf("primary group name '%s'\n", pgroupname);
    )

    (void)_flushall();

    retval = 0;

    switch(st) {
        case SHELLTYPE_SYSTEM:
            if (av[cmd_arg_index] != NULL) {
                size_t cmdbuff_size = strlen(CYGWIN_BASH_PATH)+
                    16+
                    strlen(av[cmd_arg_index])*2;
                char *cmdbuff = alloca(cmdbuff_size);
                char *s = cmdbuff;
                s = stpcpy(s, CYGWIN_BASH_PATH);
                s = stpcpy(s, " -c ");

                win32cmd_quotearg(s, av[cmd_arg_index]);
                D((void)fprintf(stderr, "# executing '%s'\n", cmdbuff));
                subcmdret = system(cmdbuff);
            }
            else {
                subcmdret = system(CYGWIN_BASH_PATH);
            }
            break;
        case SHELLTYPE_CMD:
            if (av[cmd_arg_index] != NULL) {
                subcmdret = _spawnl(_P_WAIT,
                    WIN32_CMDEXE_PATH, WIN32_CMDEXE_PATH,
                    "/C", av[cmd_arg_index], NULL);
            }
            else {
                subcmdret = _spawnl(_P_WAIT,
                    WIN32_CMDEXE_PATH, WIN32_CMDEXE_PATH, NULL);
            }
            break;
        case SHELLTYPE_NONE:
            subcmdret = _spawnl(_P_WAIT,
                WIN32_CMDEXE_PATH, WIN32_CMDEXE_PATH, NULL);
            break;
        default:
            assert(0);
            break;
    }

    D((void)fprintf(stdout, "#mark winsg done, subcmdret=%d\n",
        (int)subcmdret));

done:
    if (tok == INVALID_HANDLE_VALUE) {
        (void)CloseHandle(tok);
    }

    return retval;
}
