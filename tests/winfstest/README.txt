#
# winfstest testsuite usage instructions
# for ms-nfs41-client
#

set -o xtrace
set -o nounset
set -o errexit

git clone https://github.com/kofemann/ms-nfs41-client.git
git clone https://github.com/dimov-cz/winfstest.git
cd winfstest/

# switch to commit which is known to work (with our patches)
git checkout '525f878c06c585619eadd769c8ed9dcdf175b026'
git am --ignore-whitespace <'../ms-nfs41-client/tests/winfstest/0001-winfstest-Update-VS-project-file-to-VS19-and-make-fi.patch'

# build test suite binaries
export PATH+=":/cygdrive/c/Program Files (x86)/Microsoft Visual Studio/2019/Community/MSBuild/Current/Bin/"
MSBuild.exe winfstest.sln -t:Build -p:Configuration=Debug -p:Platform=x64

# get testsuite binary path
cd TestSuite
winfstest_testsuite_path="$(pwd)"

# create test dir on NFSv4.1 filesystem
mkdir -p /cygdrive/t/winfstesttmp
cd /cygdrive/t/winfstesttmp

# run testsuite
${winfstest_testsuite_path}/run-winfstest

# EOF.
