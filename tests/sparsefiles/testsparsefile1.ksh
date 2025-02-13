#!/bin/ksh93

#
# MIT License
#
# Copyright (c) 2025 Roland Mainz <roland.mainz@nrubsig.org>
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
# testsparsefile1.ksh - simple sparsefile test
#
# Written by Roland Mainz <roland.mainz@nrubsig.org>
#



PATH='/bin:/usr/bin'

builtin rm

function test_sparsefile1
{
    set -o errexit
    set -o nounset
    #set -o xtrace

    compound c

    integer c.fsblocksize=$1
    integer c.start_data_section=$2
    integer c.end_data_section=$3

    integer i
    compound -a c.filecontent

    #
    # generate sparse file layout+contents
    #
    for (( i=c.start_data_section ; i < c.end_data_section ; i++ )) ; do
        c.filecontent[$i]=(
            integer pos=i*1024*c.fsblocksize
            typeset data="$(printf "#block %d*1024*%d\n" i c.fsblocksize)"
        )
    done


    #
    # generate sparse file
    #
    rm -f 'mysparsefile'
    printf '' >'mysparsefile' # trunc

    for i in ${!c.filecontent[@]} ; do
        dd of='mysparsefile' bs=1 conv=notrunc seek=${c.filecontent[$i].pos} status=none <<<"${c.filecontent[$i].data}"
    done


    #
    # print results
    #
    printf '#\n# Results:\n#\n'

    ls -l mysparsefile

    /cygdrive/c/Windows/system32/fsutil sparse queryrange 'mysparsefile'

    integer fsutil_num_data_sections="$(/cygdrive/c/Windows/system32/fsutil sparse queryrange 'mysparsefile' | wc -l)"


    #
    # test whether the file is OK
    #
    if (( fsutil_num_data_sections != (c.end_data_section-c.start_data_section) )) ; then
        printf "# TEST failed, found %d data sections, expceted %d\n" \
            fsutil_num_data_sections \
            $((c.end_data_section-c.start_data_section))
        return 1
    fi

    printf "\n#\n# TEST OK, found %d data sections\n#\n" \
        fsutil_num_data_sections
    return 0
}


#
# main
#
set -o errexit
test_sparsefile1 1024 0 4
test_sparsefile1 1024 1 4
test_sparsefile1 1024 0 32
test_sparsefile1 1024 2 32

# 512 does not work, as Win10 fsutil can only handle 64 data sections
# test_sparsefile1 1024 2 512

printf '%s: All tests OK\n' "$0"
exit 0
# EOF.
