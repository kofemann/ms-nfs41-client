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
#include <stddef.h>
#include <ctype.h>

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
VOID WINAPI EventCallback(PEVENT_RECORD ev)
{
    unsigned char buffer[2048];
    unsigned char *b = buffer;

    if (ev->UserDataLength >= offsetof(DBGPRINT_EVENT, Message)) {
        size_t i;
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

int main(int ac, char *av[])
{
    TRACEHANDLE hSession = 0;
    TRACEHANDLE hTrace = 0;
    ULONG status;
    int retval = EXIT_SUCCESS;

    (void)ac;

    size_t propsSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    EVENT_TRACE_PROPERTIES *props = (EVENT_TRACE_PROPERTIES*)calloc(1, propsSize);
    if (props == NULL) {
        (void)fprintf(stderr, "%s: Malloc failed\n", av[0]);
        retval = EXIT_FAILURE;
        goto done;
    }

    props->Wnode.BufferSize = (ULONG)propsSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->EnableFlags = EVENT_TRACE_FLAG_DBGPRINT;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
#if 1
    /* Increase buffer size to 32MB */
    props->BufferSize = 64;             /* Buffer size in KB (64KB per buffer) */
    props->MinimumBuffers = 512;        /* Minimum buffers */
    props->MaximumBuffers = 512;        /* Maximum buffers */
#endif

    status = StartTraceW(&hSession, KERNEL_LOGGER_NAME, props);
    if (status == ERROR_ALREADY_EXISTS) {
        (void)fprintf(stderr,
            "#### Kernel Logger already running, attaching...\n");
        hSession = 0;
    } else if (status != ERROR_SUCCESS) {
        (void)fprintf(stderr, "%s: StartTraceA() failed with error=%d\n",
            av[0], (int)status);
        retval = EXIT_FAILURE;
        goto done;
    } else {
        (void)fprintf(stderr,
            "#### Started Kernel Logger session.\n");
    }

    EVENT_TRACE_LOGFILE log = {
        .LoggerName = KERNEL_LOGGER_NAME,
        .ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME |
            PROCESS_TRACE_MODE_EVENT_RECORD,
        .EventRecordCallback = EventCallback
    };

    hTrace = OpenTrace(&log);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
        (void)fprintf(stderr, "%s: OpenTrace() failed with error=%d\n",
            av[0], (int)GetLastError());
        retval = EXIT_FAILURE;
        goto done;
    }

    (void)fprintf(stderr,
        "#### Listening for |DbgPrint*()| messages...\n");
    status = ProcessTrace(&hTrace, 1, NULL, NULL);

done:
    return retval;
}
