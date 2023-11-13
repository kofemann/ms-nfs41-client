# ms-nfs41-client/cygwin/README.txt

#### Building ms-nfs41-client using Cygwin:
** Required software:
- Visual Studio 19
- WDK for Windows 10, version 2004, from
  https://go.microsoft.com/fwlink/?linkid=2128854

** Building the project using GUI:
1. Start Visual Studio 19
2. Load the project file "build.vc19/nfs41-client.sln"
3. Select menu item "Build/Build solution" as "Debug/x64"
4. Select menu item "Build/Build solution" as "Release/x64"

** Build the project using Cygwin command line (bash/ksh93):
export PATH+=":/cygdrive/c/Program Files (x86)/Microsoft Visual Studio/2019/Community/MSBuild/Current/Bin/"
git clone https://github.com/kofemann/ms-nfs41-client.git
cd ms-nfs41-client
MSBuild.exe build.vc19/nfs41-client.sln -t:Build -p:Configuration=Debug -p:Platform=x64
MSBuild.exe build.vc19/nfs41-client.sln -t:Build -p:Configuration=Release -p:Platform=x64

** Make release blob:
mkdir dist
cd dist/
cp ../build.vc19/x64/Debug/nfsd.exe nfsd_debug.exe
cp ../build.vc19/x64/Release/* .
cp ../nfs41rdr.inf .
cp ../etc_netconfig .
cp ../ms-nfs41-idmap.conf .


#### Install release blob (requires mintty.exe running as "Adminstrator"):
cd ms-nfs41-client/dist
bash ../cygwin/devel/msnfs41client.bash install


#### Run nfs41 client:
** Run deamon:
(requires to modify "msnfs41client.bash")
bash ../cygwin/devel/msnfs41client.bash run_daemon


** mount home dir:
(requires to modify "msnfs41client.bash")
bash ../cygwin/devel/msnfs41client.bash mount_homedir


#### Testing:
** "cthon04" test suite:
git clone https://github.com/kofemann/ms-nfs41-client.git
git clone git://git.linux-nfs.org/projects/steved/cthon04.git
cd cthon04/
git config --global --add safe.directory "$PWD"
git checkout 8cefaa2ecf8d5c1240f1573530f07cfbbfc092ea
git am ../ms-nfs41-client/tests/cthon04/*.patch
make 2>&1 | tee buildlog.log
mkdir testdir1
./runtests -a -t "$PWD/testdir1" 2>&1 | tee testrun.log


#### ToDo:
- POSIX Makefile for easier build, release blob generaetion, local test
installation, running cthon4 etc
- DocBook/XML based documentation
- Document how to get and build ksh93 for Cygwin
- Cygwin-specific binary release blob
- Document the usage of utils/mount_sshnfs/ and utils/sshnfs/
- Add test code for SID etc mapping

# EOF.
