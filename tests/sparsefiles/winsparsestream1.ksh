#!/bin/ksh93

#
# MIT License
#
# Copyright (c) 2025-2026 Roland Mainz <roland.mainz@nrubsig.org>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

#
# winsparsestream.ksh - test many combinations of sparse streams via Windows
# (non-Cygwin) APIs
#
# Written by Roland Mainz <roland.mainz@nrubsig.org>
#

function test_sparse_streams
{
    set -o xtrace
    set -o errexit
    set -o nounset

    compound fsutilout

    rm -f ii
    touch ii
    #
    # $ icacls ".\\ii" /grant "$(logname):(X,DC)" # is required for fsutil
    # on NTFS, otherwise we get a "Permission denied"
    #
    icacls ".\\ii" /grant "$(logname):(X,DC)"

    for streamname in "ii:yyy6" "ii:yyy7" "ii:yyy8" "ii:yyy9" ; do
        powershell -Command "Remove-Item -Path .\\${streamname} -ErrorAction SilentlyContinue" || true

        fsutil file createnew ${streamname} 0
        fsutil sparse setflag ${streamname} 1
        cmd /C "C:\cygwin64\bin\printf.exe \"MARK1\\n\" >>${streamname}"

        fsutil file seteof ${streamname} 0x100000000
        cmd /C "C:\cygwin64\bin\printf.exe \"MARK2\\n\" >>${streamname}"

        fsutil file seteof ${streamname} 0x200000000
        cmd /C "C:\cygwin64\bin\printf.exe \"MARK3\\n\" >>${streamname}"

        fsutil file seteof ${streamname} 0x300000000
        cmd /C "C:\cygwin64\bin\printf.exe \"MARK4\\n\" >>${streamname}"

        fsutil file seteof ${streamname} 0x400000000
        cmd /C "C:\cygwin64\bin\printf.exe \"EOF.\\n\" >>${streamname}"

        # check whether we really have five data sections
        fsutilout.stderr="${ fsutilout.stdout="${ fsutil sparse queryrange ${streamname} || true ; }" 2>&1 ; }"
        #print -v fsutilout
        if (( $(wc -l <<<"${fsutilout.stdout}") != 5 )) ; then
            print -u2 -f $"Test failed, expected 5 lines of output\n"
            return 1
        fi

        # punch a hole over the data section containing "MARK3" ...
        fsutil sparse setrange ${streamname} $((0x200000000-0x100000)) $((2*0x100000))

        # ... and verify that we now only have four data sections left:
        fsutilout.stderr="${ fsutilout.stdout="${ fsutil sparse queryrange ${streamname} || true ; }" 2>&1 ; }"
        #print -v fsutilout
        if (( $(wc -l <<<"${fsutilout.stdout}") != 4 )) ; then
            print -u2 -f $"Test failed, expected 4 lines of output\n"
            return 1
        fi
    done

    printf '#\n# TEST OK\n#\n'
    return 0
}


#
# main
#

builtin wc

test_sparse_streams

#EOF.
