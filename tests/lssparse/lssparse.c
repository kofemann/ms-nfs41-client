
/*
 * MIT License
 *
 * Copyright (c) 2011-2025 Roland Mainz <roland.mainz@nrubsig.org>
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
 * lssparse.c - print sparse file hole+data layout information
 *
 * Written by Roland Mainz <roland.mainz@nrubsig.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define EXIT_USAGE (2)

static
void usage(const char *progname)
{
    (void)fprintf(stderr, "Usage: %s [-h] <sparse_file>\n"
        "  -h: Display this help message\n"
        "  -x: Print offsets in hexadecimal (base 16)\n"
        "  -d: Print offsets in decimal (base 10)\n"
        "  -H: Print hole information\n",
        progname);
}

typedef enum _printbase {
    pb_hex = 1,
    pb_dec = 2
} printbase;

int main(int argc, char *argv[])
{
    /* Arguments */
    const char *progname = argv[0];
    printbase pb = pb_hex;
    bool print_holes = false;
    const char *filename;

    int retval;
    int opt;
    int fd;

    size_t i;
    off_t offset = 0;
    off_t data_start;
    off_t hole_start;
    off_t hole_end;
    off_t file_size;
    off_t data_len;
    off_t hole_len;

    while ((opt = getopt(argc, argv, "hxdH")) != -1) {
        switch (opt) {
            case '?':
            case 'h':
                usage(progname);
                return EXIT_USAGE;
            case 'x':
                pb = pb_hex;
                break;
            case 'd':
                pb = pb_dec;
                break;
            case 'H':
                print_holes = true;
                break;
            default:
                break;
        }
    }

    if (optind >= argc) {
        usage(progname);
        return EXIT_USAGE;
    }

    filename = argv[optind];

    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        (void)fprintf(stderr, "%s: Open file failed with [%s]\n",
            progname,
            strerror(errno));
        return EXIT_FAILURE;
    }

    /* Get file size */
    file_size = lseek(fd, 0, SEEK_END);
    if (file_size == -1) {
        (void)fprintf(stderr, "%s: Cannot seek [%s]\n",
            progname,
            strerror(errno));
        return EXIT_FAILURE;
    }
    (void)lseek(fd, 0, SEEK_SET);


    /*
     * Loop over hole&&data sections
     *
     * This loop must handle:
     * - normal files with no holes
     * - sparse files which start with data
     * - sparse files which start with a hole
     * - sparse files with multiple holes
     * - sparse files which end with data
     * - sparse files which end with a hole
     *
     * Note we start with index |1| for compatibility
     * with SUN's original sparse file debuggung tools
     * and Win32's
     * $ /cygdrive/c/Windows/system32/fsutil sparse queryrange ... #
     * output
     */
#define LSSPARSE_START_INDEX 1
    for (i=LSSPARSE_START_INDEX ;;) {
        data_start = lseek(fd, offset, SEEK_DATA);
        if (data_start == -1)
            break;
        hole_start = lseek(fd, data_start, SEEK_HOLE);

        if (hole_start == -1) {
            if (errno == ENXIO) {
                /* No more holes ? Use file site as pos of next hole */
                hole_start = file_size;
            } else {
                (void)fprintf(stderr,
                    "%s: lseek(..., SEEK_HOLE, ...) failed with [%s]\n",
                    progname,
                    strerror(errno));
                    retval = EXIT_FAILURE;
                goto done;
            }
        }

        if (print_holes &&
            (i == LSSPARSE_START_INDEX) && (data_start > 0)) {
            (void)printf((pb == pb_hex)?
                "Hole range[%ld]: offset=0x%llx,\tlength=0x%llx\n":
                "Hole range[%ld]: offset=%lld,\tlength=%lld\n",
                (long)i,
                (long long)0,
                (long long)data_start);
            i++;
        }

        data_len = hole_start - data_start;

        (void)printf((pb == pb_hex)?
            "Data range[%ld]: offset=0x%llx,\tlength=0x%llx\n":
            "Data range[%ld]: offset=%lld,\tlength=%lld\n",
            (long)i,
            (long long)data_start,
            (long long)data_len);
        i++;

        hole_end = lseek(fd, hole_start, SEEK_DATA);

        if (hole_end == -1) {
            if (errno == ENXIO) {
                /* No more holes ? */
                hole_end = file_size;
            } else {
                (void)fprintf(stderr,
                    "%s: lseek(..., SEEK_DATA, ...) failed with [%s]\n",
                    progname,
                    strerror(errno));
                retval = EXIT_FAILURE;
                goto done;
            }
        }

        hole_len = hole_end - hole_start;

        if (print_holes && (hole_len > 0LL)) {
            (void)printf((pb == pb_hex)?
                "Hole range[%ld]: offset=0x%llx,\tlength=0x%llx\n":
                "Hole range[%ld]: offset=%lld,\tlength=%lld\n",
                (long)i,
                (long long)hole_start,
                (long long)hole_len);
            i++;
        }

        offset = hole_end;
    }

    if ((data_start == -1) && (errno == ENXIO) && (offset == 0)) {
        if (print_holes) {
            (void)printf((pb == pb_hex)?
                "Hole range[%ld]: offset=0x%llx,\tlength=0x%llx\n":
                "Hole range[%ld]: offset=%lld,\tlength=%lld\n",
                (long)LSSPARSE_START_INDEX,
                (long long)0LL,
                (long long)file_size);
        }

        retval = EXIT_SUCCESS;
    } else if ((data_start == -1) && (errno != ENXIO)) {
        (void)fprintf(stderr,
            "%s: lseek(..., SEEK_DATA, ...) failed with [%s]\n",
            progname,
            strerror(errno));
            retval = EXIT_FAILURE;
    }
    else {
        retval = EXIT_SUCCESS;
    }

done:
    (void)close(fd);
    return retval;
}
