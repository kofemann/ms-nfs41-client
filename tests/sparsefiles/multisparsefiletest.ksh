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
# multisparsefiletest1.ksh - test many combinations of sparse file layouts
#
# Written by Roland Mainz <roland.mainz@nrubsig.org>
#

function multisparsefiletest1
{
    set -o nounset
    set -o errexit

    integer -r dd_blksize=1024

    integer tests_ok=0
    integer tests_failed=0
    integer tests_skipped=0

    compound c=(
        integer i
        typeset testlabel

        integer found_num_holes # found number of hole ranges
        integer found_num_data  # found number of data ranges
    )

    compound -A expected_results=(
        ['emptyfile']=(
            integer num_holes=1
            integer num_data=0
        )
        ['dataat0pos,']=(
            integer num_holes=0
            integer num_data=1
        )
        ['helloat256kpos,']=(
            integer num_holes=1
            integer num_data=1
        )
        ['dataat0pos,helloat256kpos,']=(
            integer num_holes=1
            integer num_data=2
        )
        ['helloat512kpos,']=(
            integer num_holes=1
            integer num_data=1
        )
        ['dataat0pos,helloat512kpos,']=(
            integer num_holes=1
            integer num_data=2
        )
        ['helloat256kpos,helloat512kpos,']=(
            integer num_holes=2
            integer num_data=2
        )
        ['dataat0pos,helloat256kpos,helloat512kpos,']=(
            integer num_holes=2
            integer num_data=3
        )
        ['holeatend,']=(
            integer num_holes=1
            integer num_data=0
        )
        ['dataat0pos,holeatend,']=(
            integer num_holes=1
            integer num_data=1
        )
        ['helloat256kpos,holeatend,']=(
            integer num_holes=2
            integer num_data=1
        )
        ['dataat0pos,helloat256kpos,holeatend,']=(
            integer num_holes=2
            integer num_data=2
        )
        ['helloat512kpos,holeatend,']=(
            integer num_holes=2
            integer num_data=1
        )
        ['dataat0pos,helloat512kpos,holeatend,']=(
            integer num_holes=2
            integer num_data=2
        )
        ['helloat256kpos,helloat512kpos,holeatend,']=(
            integer num_holes=3
            integer num_data=2
        )
        ['dataat0pos,helloat256kpos,helloat512kpos,holeatend,']=(
            integer num_holes=3
            integer num_data=3
        )


        ['appenddataatend']=(
            integer num_holes=0
            integer num_data=1
        )
        ['dataat0pos,appenddataatend']=(
            integer num_holes=0
            integer num_data=1
        )
        ['helloat256kpos,appenddataatend']=(
            integer num_holes=1
            integer num_data=1
        )
        ['dataat0pos,helloat256kpos,appenddataatend']=(
            integer num_holes=1
            integer num_data=2
        )
        ['helloat512kpos,appenddataatend']=(
            integer num_holes=1
            integer num_data=1
        )
        ['dataat0pos,helloat512kpos,appenddataatend']=(
            integer num_holes=1
            integer num_data=2
        )
        ['helloat256kpos,helloat512kpos,appenddataatend']=(
            integer num_holes=2
            integer num_data=2
        )
        ['dataat0pos,helloat256kpos,helloat512kpos,appenddataatend']=(
            integer num_holes=2
            integer num_data=3
        )
        ['holeatend,appenddataatend']=(
            integer num_holes=1
            integer num_data=1
        )
        ['dataat0pos,holeatend,appenddataatend']=(
            integer num_holes=1
            integer num_data=2
        )
        ['helloat256kpos,holeatend,appenddataatend']=(
            integer num_holes=2
            integer num_data=2
        )
        ['dataat0pos,helloat256kpos,holeatend,appenddataatend']=(
            integer num_holes=2
            integer num_data=3
        )
        ['helloat512kpos,holeatend,appenddataatend']=(
            integer num_holes=2
            integer num_data=2
        )
        ['dataat0pos,helloat512kpos,holeatend,appenddataatend']=(
            integer num_holes=2
            integer num_data=3
        )
        ['helloat256kpos,helloat512kpos,holeatend,appenddataatend']=(
            integer num_holes=3
            integer num_data=3
        )
        ['dataat0pos,helloat256kpos,helloat512kpos,holeatend,appenddataatend']=(
            integer num_holes=3
            integer num_data=3
        )
    )

    for ((c.i=0 ; c.i < 31 ; c.i++ )) ; do
        rm -f \
            'sparsefile2.bin' \
            'sparsefile2_cpsparse.bin' \
            'sparsefile2_cloned_full.bin' \
            'sparsefile2_cloned_1mbchunks.bin'
        c.testlabel=''

        if (( c.i == 0 )) ; then
            c.testlabel='emptyfile'
            touch 'sparsefile2.bin'
        fi

        if (( c.i & 1 )) ; then
            printf 'start\n' >'sparsefile2.bin'
            c.testlabel='dataat0pos,'
        else
            testlabel='holeat0pos,'
        fi
        if (( c.i & 2 )) ; then
            # Cygwin has a minimum hole size of 128k on NTFS, so we cannot use smaller values
            printf "hello\n" | dd of='sparsefile2.bin' seek=$((256)) bs=${dd_blksize} 2>'/dev/null'
            c.testlabel+='helloat256kpos,'
        fi
        if (( c.i & 4 )) ; then
            printf "world\n" | dd of='sparsefile2.bin' seek=$((512)) bs=${dd_blksize} 2>'/dev/null'
            c.testlabel+='helloat512kpos,'
        fi
        if (( c.i & 8 )) ; then
            dd if=/dev/null of='sparsefile2.bin' seek=$((2048)) bs=${dd_blksize} 2>'/dev/null'
            c.testlabel+='holeatend,'
        fi
        if (( c.i & 16 )) ; then
            printf 'appenddataatend\n' >>'sparsefile2.bin'
            c.testlabel+='appenddataatend'
        fi

        typeset tstmod

        typeset -a tstmodlist=(
            'plainfile'
            'cp_sparseauto'
            'cloned_full'
            'cloned_1mbchunks'
        )

        for tstmod in "${tstmodlist[@]}" ; do
            printf '# Test %d '%s' generated\n' c.i "${c.testlabel}/$tstmod"

            case "${tstmod}" in
                'plainfile')
                    c.stdout="$(lssparse -H 'sparsefile2.bin')"
                    ;;
                'cp_sparseauto')
                    /usr/bin/cp --sparse='auto' 'sparsefile2.bin' 'sparsefile2_cpsparse.bin'
                    c.stdout="$(lssparse -H 'sparsefile2_cpsparse.bin')"
                    ;;
                'cloned_full')
                    if $test_cloning ; then
                        winclonefile.exe 'sparsefile2.bin' 'sparsefile2_cloned_full.bin' 1>'/dev/null'
                        c.stdout="$(lssparse -H 'sparsefile2_cloned_full.bin')"
                    else
                        printf "# Test '%s' SKIPPED\n" "${c.testlabel}/${tstmod}"
                        (( tests_skipped++ ))
                        continue
                    fi
                    ;;
                'cloned_1mbchunks')
                    if $test_cloning ; then
                        winclonefile.exe \
                            --clonechunksize $((1024*1024)) \
                            'sparsefile2.bin' \
                            'sparsefile2_cloned_1mbchunks.bin' 1>'/dev/null'
                        c.stdout="$(lssparse -H 'sparsefile2_cloned_1mbchunks.bin')"
                    else
                        printf "# Test '%s' SKIPPED\n" "${c.testlabel}/${tstmod}"
                        (( tests_skipped++ ))
                        continue
                    fi
                    ;;
                *)
                    print -u2 -f 'Unknown test mod\n'
                    ;;
            esac

            c.found_num_holes=$(grep -F 'Hole range' <<<"${c.stdout}" | wc -l)
            c.found_num_data=$(grep -F 'Data range' <<<"${c.stdout}" | wc -l)

            if (( expected_results[${c.testlabel}].num_holes != c.found_num_holes ||
                    expected_results[${c.testlabel}].num_data != c.found_num_data )) ; then
                printf "# Test '%s' ERROR, expeced %d hole ranges and %d data ranges, got\n" \
                    "${c.testlabel}/${tstmod}" \
                    ${expected_results[${c.testlabel}].num_holes} \
                    ${expected_results[${c.testlabel}].num_data}
                print -v c
                (( tests_failed++ ))
            else
                printf "# Test '%s' OK\n" "${c.testlabel}/${tstmod}"
                (( tests_ok++ ))
            fi
        done
    done

    printf '\n######## Tests OK=%d, skipped tests=%d, failed tests=%d\n' \
        tests_ok tests_skipped tests_failed
    return 0
}


#
# main
#
builtin rm
builtin wc

#
# ToDo list:
# - Test whether filesystem supports block cloning and
# winclonefile.exe is available
# - variable block size
# - verify file sizes (original vs copy/clone)
# - tests for sparse files >= 2GB, 4GB, 16GB
#
typeset test_cloning=false

multisparsefiletest1

#EOF.
