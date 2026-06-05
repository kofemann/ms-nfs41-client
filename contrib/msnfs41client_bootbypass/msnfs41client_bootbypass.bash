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

# Author: Takeshi Nishimura <takeshi.nishimura.linux@gmail.com>

rm -f BootBypass.7z
wget 'https://github.com/wesmar/BootBypass/releases/download/latest/BootBypass.7z'
if [[ "$(sha256sum BootBypass.7z)" != *'340d2ce4575d767d8054dab1fe175ba8436737e812daaeb9d8e1f617045b36d9'* ]] ; then
    echo "ERR: Download hash does not match" 1>&1
    exit 1
fi

rm -f bb.exe deploy.ps1 drivers.ini
7za -pgithub.com e BootBypass.7z

powershell -ExecutionPolicy Bypass -File '.\deploy.ps1' -TargetDriverNtPath '\SystemRoot\System32\drivers\nfs41_driver.sys' -Force
bcdedit /set testsigning off
