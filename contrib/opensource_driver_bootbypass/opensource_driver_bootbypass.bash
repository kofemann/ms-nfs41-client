#!/bin/bash
#
# MIT License
#
# Copyright (c) 2026 Osaka University
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
# opensource_driver_bootbypass.bash - use opensource drivers with Secureboot
# for OpenZFS, WinBTRFS, ms-nfs41-client, filedisk/filedisk-sparse
#

# Author: Takeshi Nishimura <takeshi.nishimura.linux@gmail.com>

get_authenticodesignature()
{
    powershell -NoProfile -Command "(Get-AuthenticodeSignature "$(cygpath -w "$1")").Status"
}

print_driversini_section()
{
    typeset driverpath="$1"
    typeset drivername="$(basename "$driverpath")"
    typeset servicename="${drivername%.sys}"

    if [[ ! -f "$driverpath" ]] ; then
        return 0
    fi

    if [[ "$(get_authenticodesignature "$driverpath")" == "Valid"* ]] ; then
        printf "#-------- Driver %s has valid Secureboot signature\n" "$drivername" 1>&2
        return 0
    fi

    printf "#-------- Adding drivers.ini section for %s\n" "$(basename "$driverpath")" 1>&2

cat <<EOF
[Driver$((driversection_count))]
Action=LOAD
AutoPatch=YES
ServiceName=${servicename}
ImagePath=\\SystemRoot\\System32\\drivers\\${drivername}
DriverType=1
StartType=1

EOF

    ((driversection_count+=1))

    return 0
}

# START:
rm -f BootBypass.7z
wget 'https://github.com/wesmar/BootBypass/releases/download/latest/BootBypass.7z'
if [[ "$(sha256sum BootBypass.7z)" != *'340d2ce4575d767d8054dab1fe175ba8436737e812daaeb9d8e1f617045b36d9'* ]] ; then
    printf "ERROR: Download hash does not match\n" 1>&2
    exit 1
fi

rm -f bb.exe deploy.ps1 drivers.ini
7za -pgithub.com e BootBypass.7z


{
# BEGIN drivers.ini generation
declare -g driversection_count=0

cat <<EOF
[Config]
Execute=YES
RestoreHVCI=YES
Verbose=NO
DriverDevice=\\Device\\kvc
IoControlCode_Read=2147491912
IoControlCode_Write=2147491916

EOF

print_driversini_section '/cygdrive/c/Windows/System32/drivers/OpenZFS.sys'
print_driversini_section '/cygdrive/c/Windows/System32/drivers/btrfs.sys'
print_driversini_section '/cygdrive/c/Windows/System32/drivers/nfs41_driver.sys'
print_driversini_section '/cygdrive/c/Windows/System32/drivers/filedisk.sys'

# END drivers.ini generation
} | sed 's/$/\r/' | { printf '\xFF\xFE' ; iconv -t UTF16LE ; } >'drivers.ini'

powershell -ExecutionPolicy Bypass -File '.\deploy.ps1' -Force
bcdedit /set testsigning off

printf "#-------- %s finished\n" "$0"

