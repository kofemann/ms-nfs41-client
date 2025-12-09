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
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
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
 * catdbgprint.c - print Windows kernel |DbgPrint()| messages
 *
 * Written by Roland Mainz <roland.mainz@nrubsig.org>
 */

/*
 * Compile with:
 * $ clang -target x86_64-pc-windows-gnu \
 *      -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -g catdbgprint.c -o catdbgprint.exe #
 */

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <ctype.h>

#define KERNEL_LOGGER_NAME_A "NT Kernel Logger"

#define EXIT_USAGE (2) /* Traditional UNIX exit code for usage */

typedef struct _DBGPRINT_EVENT {
    ULONG ComponentId;   /* DPFLTR_xxx_ID */
    ULONG Level;         /* DPFLTR_LEVEL_xxx */
    CHAR  Message[];     /* '\0'-terminated ANSI string */
} DBGPRINT_EVENT;

static
void int_to_octal3(int value, unsigned char *restrict out)
{
    if (value < 0)
        value = 0;
    if (value > 0777)
        value = 0777; /* clamp to max 0777/511 */

    out[2] = (char)('0' + (value & 7));
    out[1] = (char)('0' + ((value >> 3) & 7));
    out[0] = (char)('0' + ((value >> 6) & 7));
}

static
VOID WINAPI trace_eventcallback(PEVENT_RECORD ev)
{
    unsigned char buffer[2048];
    unsigned char *b = buffer;

    if (ev->UserDataLength >= offsetof(DBGPRINT_EVENT, Message)) {
        ssize_t i;
        unsigned char c;
        const DBGPRINT_EVENT *dpe = (const DBGPRINT_EVENT *)ev->UserData;
        const unsigned char *msg = (const unsigned char *)dpe->Message;
        ssize_t msg_len = ev->UserDataLength - offsetof(DBGPRINT_EVENT, Message);

        for (i=0 ; i < msg_len ; i++) {
            if ((msg[i] == '\0') ||
                ((msg[i] == '\n') && (msg[i+1] == '\0')))
                break;

            c = msg[i];

            if (c == '\n') {
                *b++ = '\\';
                *b++ = 'n';
            }
            else if (c == '\v') {
                *b++ = '\\';
                *b++ = 'v';
            }
            else if (c == '\f') {
                *b++ = '\\';
                *b++ = 'f';
            }
            else if (c == '\r') {
                *b++ = '\\';
                *b++ = 'r';
            }
            else if (c == '\t') {
                *b++ = '\\';
                *b++ = 't';
            }
            else if (c == '\b') {
                *b++ = '\\';
                *b++ = 'b';
            }
            else if (c == '\a') {
                *b++ = '\\';
                *b++ = 'a';
            }
            else if (c == '\\') {
                /*
                 * We only print one backslash, otherwise we cause problems
                 * with the user expectation that they can copy&&paste Windows
                 * paths.
                 * FIXME: There should be a command-line argument to define
                 * how to handle non-printable+backslash characters (e.g.
                 * "human readable", "always octal escaped",
                 * "ksh93 compound variable array", ...)
                 */
                *b++ = '\\';
            }
            else if ((c > 127) || isprint((int)c)) {
                *b++ = c;
            }
            else {
                *b++ = '\\';
                int_to_octal3(c, b);
                b+=3;
            }
        }

        *b++ = '\0';
        (void)fprintf(stdout, "%s\n", buffer);
    }
}


static
int do_starttrace(const char *progname)
{
    ULONG status = 0;

    size_t propsSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    EVENT_TRACE_PROPERTIES *props = (EVENT_TRACE_PROPERTIES*)calloc(1, propsSize);
    if (!props) {
        (void)fprintf(stderr, "%s:[!] malloc() EVENT_TRACE_PROPERTIES failed\n",
            progname);
        return EXIT_FAILURE;
    }

    *props = (EVENT_TRACE_PROPERTIES){
        .Wnode = (WNODE_HEADER){
            .BufferSize = (ULONG)propsSize,
            .Flags      = WNODE_FLAG_TRACED_GUID
        },
        .LogFileMode    = EVENT_TRACE_REAL_TIME_MODE,
        .EnableFlags    = EVENT_TRACE_FLAG_DBGPRINT,
        .BufferSize     = 64,   /* KB per buffer */
        .MinimumBuffers = 512,  /* 64KB * 512 = 32MB */
        .MaximumBuffers = 512
    };

    TRACEHANDLE hSession = 0;
    status = StartTraceA(&hSession, KERNEL_LOGGER_NAME_A, props);
    if (status == ERROR_ALREADY_EXISTS) {
        (void)fprintf(stderr, "#### Kernel Logger already running\n");
        free(props);
        return EXIT_SUCCESS;
    }
    else if (status != ERROR_SUCCESS) {
        (void)fprintf(stderr, "%s: StartTraceA() failed, lasterr=%d\n",
            progname,
            (int)status);
        free(props);
        return EXIT_FAILURE;
    }

    (void)fprintf(stderr, "#### Started Kernel Logger\n");
    free(props);

    return EXIT_SUCCESS;
}

static TRACEHANDLE g_hTrace = 0;

static
BOOL WINAPI processtrace_ctrlhandler(DWORD type)
{
    if ((type == CTRL_C_EVENT) ||
        (type == CTRL_BREAK_EVENT) ||
        (type == CTRL_CLOSE_EVENT)) {

        (void)fprintf(stderr, "#### <CTRL-C>\n");
        if (g_hTrace) {
            (void)CloseTrace(g_hTrace);
            g_hTrace = 0;
        }

        exit(EXIT_SUCCESS);
    }

    return FALSE;
}

static
int do_processtrace(const char *progname)
{
    ULONG status;
    EVENT_TRACE_LOGFILEA log = {
        .LoggerName        = (LPSTR)KERNEL_LOGGER_NAME_A,
        .ProcessTraceMode  = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
        .EventRecordCallback = trace_eventcallback
    };

    g_hTrace = OpenTraceA(&log);
    if (g_hTrace == INVALID_PROCESSTRACE_HANDLE) {
        (void)fprintf(stderr, "%s: OpenTraceA() failed, lasterr=%d\n",
            progname, (int)GetLastError());
        return EXIT_FAILURE;
    }

    (void)SetConsoleCtrlHandler(processtrace_ctrlhandler, TRUE);

    status = ProcessTrace(&g_hTrace, 1, NULL, NULL);
    (void)fprintf(stderr, "#### ProcessTrace() returned, lasterr=%d\n",
        (int)status);

    (void)CloseTrace(g_hTrace);
    g_hTrace = 0;

    /* Treat non-zero status as failure */
    return (status == ERROR_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static
int do_stoptrace(const char *progname)
{
    EVENT_TRACE_PROPERTIES props = {
        .Wnode = (WNODE_HEADER){ .BufferSize = sizeof(EVENT_TRACE_PROPERTIES) }
    };
    ULONG status = StopTraceA(0, KERNEL_LOGGER_NAME_A, &props);

    if ((status != ERROR_SUCCESS) && (status != ERROR_MORE_DATA)) {
        (void)fprintf(stderr, "%s: StopTraceA() failed, lasterr=%d\n",
            progname, (int)status);
        return EXIT_FAILURE;
    }

    (void)fprintf(stderr, "#### Stopped Kernel Logger.\n");

    return EXIT_SUCCESS;
}

static
void usage(const char *progname)
{
    (void)fprintf(stderr,
        "Usage:\n"
        "\t%s starttrace   - start NT Kernel Logger with DbgPrint capture\n"
        "\t%s processtrace - open and process DbgPrint events\n"
        "\t%s stoptrace    - stop NT Kernel Logger session\n",
        progname, progname, progname);
}

int main(int argc, char *av[])
{
    if (argc < 2) {
        usage(av[0]);
        return EXIT_USAGE;
    }

    /*
     * Subcmd dispatcher
     */
    if (strcmp(av[1], "starttrace") == 0) {
        return do_starttrace(av[0]);
    } else if (strcmp(av[1], "processtrace") == 0) {
        return do_processtrace(av[0]);
    } else if (strcmp(av[1], "stoptrace") == 0) {
        return do_stoptrace(av[0]);
    } else {
        (void)fprintf(stderr, "%s: Unknown option '%s\n", av[0], av[1]);
        return EXIT_FAILURE;
    }
}
