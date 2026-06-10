#!/bin/bash

#
# MIT License
#
# Copyright (c) 2023-2026 Roland Mainz <roland.mainz@nrubsig.org>
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
# mount_rovnfsshares.bash - ROVEMA lab-specific mount config sample
#

#
# Written by Roland Mainz <roland.mainz@nrubsig.org>
#

export PATH+=':/home/roland_mainz/work/msnfs41_uidmapping/ms-nfs41-client/destdir/sbin'

set -o xtrace
#set -o errexit

typeset nfsmountexe

# local or global mount ?
case "$1" in
    'local')
        nfsmountexe='nfs_mount'
        ;;
    'global')
        nfsmountexe='nfs_globalmount'
        ;;
    *)
        printf $"$0: ERROR, requires 'local' or 'global' as argument" "$0" 1>&1
        exit 1
esac

# check whether we should mount homedirs
if [[ "$1" == 'local' ]] ; then
    case "$(logname)" in
        'roland_mainz')
            ${nfsmountexe} -o rw 'H' derfwpc5131_ipv4:/export/home2/rmainz
            ${nfsmountexe} -o rw,writethru,nocache 'i' derfwpc5131_ipv4:/export/home2/rmainz
            ;;
        'siegfried_wulsch')
            ${nfsmountexe} -o rw 'H' derfwpc5131_ipv4:/export/home/swulsch
            ;;
    esac
fi

#
# mount shared dirs
#
${nfsmountexe} -p -o rw,sec=sys T derfwnb4966_ipv6linklocal:/net_tmpfs2
${nfsmountexe} -p -o sec=sys,rw R derfwnb4966_ipv6linklocal:/net_tmpfs2/test2
${nfsmountexe}.i686.exe -o sec=sys,rw 'L' nfs://derfwnb4966_ipv6linklocal//bigdisk
${nfsmountexe} -o sec=sys,rw,port=2049 'M' nfs://derfwnb4966_ipv4:1234//bigdisk
${nfsmountexe} -o sec=sys,rw,writethru,nocache 'O' nfs://derfwnb4966_ipv6linklocal//bigdisk
${nfsmountexe} -o rw 'J:' 'nfs://10.49.202.230//bigdisk/%e3%81%a0%e3%81%84%e3%81%99%e3%81%8d!%e3%83%9e%e3%82%a6%e3%82%b9/'
${nfsmountexe} -o sec=sys,rw,public=1 'P' nfs://10.49.202.230/bigdisk
${nfsmountexe} -o rw 'F:' 'nfs://10.49.202.239//nfsdata'
${nfsmountexe} -o rw,unctagnum=4000 'E' 'nfs://10.49.202.239//test_casei001_pool'

printf '#done\n'
