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


function test_sparse_holeonly_dd
{
    set -o errexit
    set -o nounset
    set -o pipefail
    #set -o xtrace

    rm -f 'sparse_file_hole_only'
    dd if='/dev/null' of='sparse_file_hole_only' bs=1 count=0 seek=$((256*1024*1024))
    chattr -V +S 'sparse_file_hole_only'

    ls -l 'sparse_file_hole_only'
    /cygdrive/c/Windows/system32/fsutil sparse queryrange 'sparse_file_hole_only'

    integer fsutil_num_data_sections="$(/cygdrive/c/Windows/system32/fsutil sparse queryrange 'sparse_file_hole_only' | wc -l)"
    integer winfsinfo_num_data_sections="$(winfsinfo fsctlqueryallocatedranges 'sparse_file_hole_only' | wc -l)"

    #
    # test whether the file is OK
    #
    if (( (fsutil_num_data_sections != 0) || (winfsinfo_num_data_sections != 0) )) ; then
        printf "# TEST failed, found fsutil=%d/winfsinfo=%d data sections, expected %d\n" \
            fsutil_num_data_sections \
            winfsinfo_num_data_sections \
            0
        return 1
    fi

    printf "\n#\n# TEST %q OK, found fsutil=%d/winfsinfo=%d data sections\n#\n" \
        "$0" \
        fsutil_num_data_sections \
        winfsinfo_num_data_sections

    return 0
}

function test_sparse_holeonly_truncate
{
    set -o errexit
    set -o nounset
    #set -o xtrace

    rm -f 'sparse_file_hole_only_trunc'
    touch 'sparse_file_hole_only_trunc'
    chattr -V +S 'sparse_file_hole_only_trunc'

    truncate -s $((256*1024*1024)) 'sparse_file_hole_only_trunc'

    ls -l 'sparse_file_hole_only_trunc'
    /cygdrive/c/Windows/system32/fsutil sparse queryrange 'sparse_file_hole_only_trunc'

    integer fsutil_num_data_sections="$(/cygdrive/c/Windows/system32/fsutil sparse queryrange 'sparse_file_hole_only_trunc' | wc -l)"
    integer winfsinfo_num_data_sections="$(winfsinfo fsctlqueryallocatedranges 'sparse_file_hole_only_trunc' | wc -l)"

    #
    # test whether the file is OK
    #
    if (( (fsutil_num_data_sections != 0) || (winfsinfo_num_data_sections != 0) )) ; then
        printf "# TEST failed, found fsutil=%d/winfsinfo=%d data sections, expected %d\n" \
            fsutil_num_data_sections \
            winfsinfo_num_data_sections \
            0
        return 1
    fi

    printf "\n#\n# TEST %q OK, found fsutil=%d/winfsinfo=%d data sections\n#\n" \
        "$0" \
        fsutil_num_data_sections \
        winfsinfo_num_data_sections

    return 0
}

function test_normal_file
{
    set -o errexit
    set -o nounset
    #set -o xtrace

    rm -f 'test_normal_file'
    dd if='/dev/zero' of='test_normal_file' bs=1024 count=1024
    chattr -V +S 'test_normal_file'

    ls -l 'test_normal_file'
    /cygdrive/c/Windows/system32/fsutil sparse queryrange 'test_normal_file'

    integer fsutil_num_data_sections="$(/cygdrive/c/Windows/system32/fsutil sparse queryrange 'test_normal_file' | wc -l)"
    integer winfsinfo_num_data_sections="$(winfsinfo fsctlqueryallocatedranges 'test_normal_file' | wc -l)"

    #
    # test whether the file is OK
    #
    if (( (fsutil_num_data_sections != 1) || (winfsinfo_num_data_sections != 1) )) ; then
        printf "# TEST failed, found fsutil=%d/winfsinfo=%d data sections, expected %d\n" \
            fsutil_num_data_sections \
            winfsinfo_num_data_sections \
            1
        return 1
    fi

    printf "\n#\n# TEST %q OK, found fsutil=%d/winfsinfo=%d data sections\n#\n" \
        "$0" \
        fsutil_num_data_sections \
        winfsinfo_num_data_sections

    return 0
}

function test_multihole_sparsefile1
{
    set -o errexit
    set -o nounset
    #set -o xtrace

    compound c

    integer c.fsblocksize=$1
    integer c.start_data_section=$2
    integer c.end_data_section=$3
    typeset c.holeatend=$4

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
    chattr -V +S 'mysparsefile'

    for i in ${!c.filecontent[@]} ; do
        dd of='mysparsefile' bs=1 conv=notrunc seek=${c.filecontent[$i].pos} status=none <<<"${c.filecontent[$i].data}"
    done

    # if we want a hole at the end, make a hole so the file itself is 8GB large
    if ${c.holeatend} ; then
        integer new_filesize=8*1024*1024*1024
        integer stat_filsize

        truncate -s ${new_filesize} 'mysparsefile'

        stat_filsize=$(stat --printf '%s\n' 'mysparsefile')

        if (( new_filesize != stat_filsize )) ; then
            printf 'Filesize after extening via truncate -s %d, expected %d\n' \
                stat_filsize new_filesize
            return 1
        fi
    fi

    #
    # print results
    #
    printf '#\n# Results:\n#\n'

    ls -l 'mysparsefile'

    /cygdrive/c/Windows/system32/fsutil sparse queryrange 'mysparsefile'

    integer fsutil_num_data_sections="$(/cygdrive/c/Windows/system32/fsutil sparse queryrange 'mysparsefile' | wc -l)"
    integer winfsinfo_num_data_sections="$(winfsinfo fsctlqueryallocatedranges 'mysparsefile' | wc -l)"


    #
    # test whether the file is OK
    #
    if (( (fsutil_num_data_sections != (c.end_data_section-c.start_data_section)) || \
        (winfsinfo_num_data_sections != (c.end_data_section-c.start_data_section)) )) ; then
        printf "# TEST failed, found fsutil=%d/winfsinfo=%d data sections, expected %d\n" \
            fsutil_num_data_sections \
            winfsinfo_num_data_sections \
            $((c.end_data_section-c.start_data_section))
        return 1
    fi

    printf "\n#\n# TEST %q OK, found fsutil=%d/winfsinfo=%d data sections\n#\n" \
        "$0" \
        fsutil_num_data_sections \
        winfsinfo_num_data_sections
    return 0
}

function test_sparse_punchhole1
{
    set -o errexit
    set -o nounset
    #set -o xtrace

    rm -f 'sparse_file_punchhole'
    touch 'sparse_file_punchhole'
    chattr -V +S 'sparse_file_punchhole'

    dd if='/dev/zero' of='sparse_file_punchhole' conv=notrunc count=32 bs=$((1024*1024)) status=none

    printf '# expected: one data section before fallocate\n'
    /cygdrive/c/Windows/system32/fsutil sparse queryrange 'sparse_file_punchhole'

    fallocate -n -p -o $((8*1024*1024)) -l $((4*1024*1024)) 'sparse_file_punchhole'

    printf '# expected: two data section after fallocate\n'
    /cygdrive/c/Windows/system32/fsutil sparse queryrange 'sparse_file_punchhole'

    integer fsutil_num_data_sections="$(/cygdrive/c/Windows/system32/fsutil sparse queryrange 'sparse_file_punchhole' | wc -l)"
    integer winfsinfo_num_data_sections="$(winfsinfo fsctlqueryallocatedranges 'sparse_file_punchhole' | wc -l)"

    #
    # test whether the file is OK
    #
    if (( (fsutil_num_data_sections != 2) || (winfsinfo_num_data_sections != 2) )) ; then
        printf "# TEST failed, found fsutil=%d/winfsinfo=%d data sections, expected %d\n" \
            fsutil_num_data_sections \
            winfsinfo_num_data_sections \
            2
        return 1
    fi

    printf "\n#\n# TEST %q OK, found fsutil=%d/winfsinfo=%d data sections\n#\n" \
        "$0" \
        fsutil_num_data_sections \
        winfsinfo_num_data_sections

    return 0
}


#
# main
#
set -o errexit

builtin basename
builtin rm
builtin wc

test_sparse_holeonly_dd
test_sparse_holeonly_truncate
test_normal_file

test_multihole_sparsefile1 1024 0 4  false
test_multihole_sparsefile1 1024 1 4  false
test_multihole_sparsefile1 1024 0 32 false
test_multihole_sparsefile1 1024 2 32 false

test_multihole_sparsefile1 1024 0 4  true
test_multihole_sparsefile1 1024 1 4  true

# 512 does not work, as Win10 fsutil can only handle 64 data sections
# test_multihole_sparsefile1 1024 2 512 false

test_sparse_punchhole1

printf '#\n# done\n#\n\n'

printf '%s: All tests OK\n' "$(basename $0)"
exit 0
# EOF.
