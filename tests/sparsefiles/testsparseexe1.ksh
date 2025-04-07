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
# testsparseexe1.ksh - test whether sparse file *.exe work
#
# Written by Roland Mainz <roland.mainz@nrubsig.org>
#

integer nulldata_array_size=1024*1024*16

function generate_test_src
{
    printf '#include <stdio.h>\n'
    printf '#include <stdlib.h>\n'
    printf '\n'

    printf 'volatile char __attribute__((section(".noinit"))) nulldata_array[%d] = {\n' nulldata_array_size
    for ((i = nulldata_array_size ; i >= 64 ; i-= 64 )) ; do
        printf '\t0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,\n'
        printf '\t0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,\n'
    done
    if (( i > 0 )) ; then
        printf '\t'
        for (( ; i > 0 ; i-- )) ; do
            printf '0,'
        done
        printf '\n'
    fi
    printf '};\n'

    printf '\nint main(int ac, char *av[])\n'
    printf '{\n'

    printf '\t(void)ac; /* not used */\n'
    printf '\t(void)av; /* not used */\n'

    printf '\tlong long sum = 0LL;\n'
    printf '\tsize_t i;\n'
    printf '\tfor (i = 0 ; i < %d ; i++) {\n' nulldata_array_size
    printf '\t\tsum += nulldata_array[i];'
    printf '\t}\n'
    printf '\t(void)printf("sum = %%lld\\n", sum);\n'
    printf '\treturn 0;\n'
    printf '}\n'

    return 0
}


function test_sparseexe1
{
    #set -o xtrace
    set -o errexit
    set -o nounset

    compound res
    integer res.errors=0

    printf '#### %s: Begin...\n' "$0"

    rm -f \
        'sparseexe_orig.exe' \
        'sparseexe_sparse.exe' \
        'sparseexe.c'

    print '# generate source...'
    generate_test_src | cat >'sparseexe.c'

    print '# compile source...'
    gcc -Wall -g 'sparseexe.c' -o 'sparseexe_orig.exe'

    #
    # HACK: Test for fallocate.exe to determinate whether the system's
    # /usr/bin/cp.exe has sparse file support (which depends on
    # SEEK_HOLE+SEEK_DATA.
    #
    if which -a 'fallocate.exe' 1>'/dev/null' ; then
        print $'# copy *.exe via cp --sparse=always, turn all sections with long sequences of 0x00-bytes into "holes" ...'
        # explicitly use /usr/bin/cp and not the AST cp builtin
        /usr/bin/cp --sparse=always 'sparseexe_orig.exe' 'sparseexe_sparse.exe'
    else
        print $'# copy *.exe via dd conv=sparse, turn all sections with long sequences of 0x00-bytes into "holes" ...'
        # explicitly use /usr/bin/cp and not the AST cp builtin
        dd if='sparseexe_orig.exe' of='sparseexe_sparse.exe' conv=sparse
        chmod a+x 'sparseexe_sparse.exe'
    fi

    print '# collect data...'
    integer res.sparseexe_orig_blocks=$(stat --printf '%b\n' 'sparseexe_orig.exe')
    integer res.sparseexe_sparse_blocks=$(stat --printf '%b\n' 'sparseexe_sparse.exe')
    integer res.sparseexe_orig_filesize=$(stat --printf '%s\n' 'sparseexe_orig.exe')
    integer res.sparseexe_sparse_filesize=$(stat --printf '%s\n' 'sparseexe_sparse.exe')
    typeset res.sparseexe_orig_md5hash=$(md5sum --total 'sparseexe_orig.exe')
    typeset res.sparseexe_sparse_md5hash=$(md5sum --total 'sparseexe_sparse.exe')

    compound res.testrun=(
        typeset stderr=''
        typeset stdout=''
        integer res=-1
    )

    set +o errexit

    res.testrun.stderr="${ { res.testrun.stdout="${ ./sparseexe_sparse.exe ; (( res.testrun.res=$? )) ; }" ; } 2>&1 ; }"

    print '# print results...'
    print -v res
    ls -ls 'sparseexe_orig.exe' 'sparseexe_sparse.exe'

    if (( res.testrun.res == 0 )) ; then
        printf 'test file return exit code 0: OK\n'
    else
        printf 'ERROR: test file return exit code %d\n' res.testrun.res
        (( res.errors++ ))
    fi

    if [[ "${res.testrun.stdout}" == ~(E)sum\ =\ 0 ]] ; then
        printf 'test file stdout %s: OK\n' "${res.testrun.stdout}"
    else
        printf 'ERROR: test file stdout output %q, expected "sum = 0"\n' "${res.testrun.stdout}"
        (( res.errors++ ))
    fi

    if [[ "${res.testrun.stderr}" == '' ]] ; then
        printf 'test file stderr empty: OK\n'
    else
        printf 'ERROR: test file stderr output %q\n' "${res.testrun.stderr}"
        (( res.errors++ ))
    fi

    if (( res.sparseexe_orig_filesize == res.sparseexe_sparse_filesize )) ; then
        printf 'test file sizes: OK\n'
    else
        printf '# ERROR: sparseexe_orig.exe and sparseexe_sparse.exe file size differ\n'
        (( res.errors++ ))
    fi

    if (( (res.sparseexe_orig_blocks/10.) > res.sparseexe_sparse_blocks )) ; then
        printf 'test file number of blocks: OK, sparseexe_sparse.exe has less filesystem blocks\n'
    else
        printf '# ERROR: sparseexe_sparse.exe consumes too many filesystem blocks\n'
        (( res.errors++ ))
    fi

    if [[ "${res.sparseexe_orig_md5hash}" == "${res.sparseexe_sparse_md5hash}" ]] ; then
        printf 'test file MD5 hash sum: OK, both hash sums are identical (%q)\n' \
            "${res.sparseexe_sparse_md5hash}"
    else
        printf '# ERROR: MD5 hash sums are NOT identical (%q != %q)\n' \
            "${res.sparseexe_orig_md5hash}" \
            "${res.sparseexe_sparse_md5hash}"
        (( res.errors++ ))
    fi

    if (( res.errors == 0 )) ; then
        printf '#### %s: All tests OK\n' "$0"
        exit 0
    else
        printf '#### %s tests FAILED\n' res.errors
        return 1
    fi

    # not reached
}

#
# main
#
builtin cat
builtin rm
builtin md5sum || exit 1 # need AST md5sum for option --total

test_sparseexe1

# EOF.
