#
# ms-nfs41-client/cygwin/README.txt
#
# Draft README/ToDo list&co.
#

######## Building ms-nfs41-client using Cygwin+Makefile:
** Required software:
* Option 1:
  Windows 10 with Visual Studio 2019
- Start Visual Studio 19 installer and import the installer
  config file "ms-nfs41-client/build.vc19/ms-nfs41-client_vs2019.vsconfig",
  and then install Visual Studio.
  (Note that due to a bug in the VS installer it is sometimes
  required to manually add another (random) component to be installed,
  otherwise the imported config might be ignored)
- WDK for Windows 10, version 2004, from
  https://go.microsoft.com/fwlink/?linkid=2128854
- Cygwin 64bit >= 3.5.0
  (see "ms-nfs41-clientcygwin/README.bintarball.txt" for Cygwin 32bit
  and 64bit installation instructions)

* Option 2:
  Windows 10/11 with Visual Studio 2022
- Start Visual Studio 2022 installer and import the installer
  config file "ms-nfs41-client/build.vc19/ms-nfs41-client_vs2022.vsconfig",
  and then install Visual Studio.
  (Note that due to a bug in the VS installer it is sometimes
  required to manually add another (random) component to be installed,
  otherwise the imported config might be ignored)
- WDK for Windows 11, version 1591, from
  https://go.microsoft.com/fwlink/?linkid=2286137
- Cygwin 64bit >= 3.5.0
  (see "ms-nfs41-clientcygwin/README.bintarball.txt" for Cygwin 32bit
  and 64bit installation instructions)


** Build the project
* using Visual Studio 2019+Cygwin command line (bash/ksh93):
# this creates a 32bit+kernel+64bit-kernel build for Windows 10+11
export PATH="/cygdrive/c/Program Files (x86)/Microsoft Visual Studio/2019/Community/MSBuild/Current/Bin/:$PATH"
git clone https://github.com/kofemann/ms-nfs41-client.git
cd ms-nfs41-client
cd cygwin
make build
make installdest
make bintarball

* using Visual Studio 2022+Cygwin command line (bash/ksh93):
# this creates a 64bit-kernel only build for Windows 11
export PATH="/cygdrive/c/Program Files/Microsoft Visual Studio/2022/Community/MSBuild/Current/Bin/:$PATH"
git clone https://github.com/kofemann/ms-nfs41-client.git
cd ms-nfs41-client
# "retarget" VS platform toolset to "v143"
# ("v142" should remain the default when comitting)
sed -i -E 's/<PlatformToolset>v142<\/PlatformToolset>/<PlatformToolset>v143<\/PlatformToolset>/g' $(find 'build.vc19' -name \*.vcxproj)
cd cygwin
make build64
make installdest64
make bintarball64

# Note that $ make installdest #/$ make installdest64 # can fail on SMB/NFSv4.1 filesystems
# with a "link.exe" crash.
# Workaround is to disable incremental linking before building, e.g. do
# ---- snip ----
cd ms-nfs41-client
sed -i -E 's/<LinkIncremental>true<\/LinkIncremental>/<LinkIncremental>false<\/LinkIncremental>/g' $(find build.vc19 -name \*.vcxproj)
# ---- snip ----
# This Visual Studio bug is tracked as
# https://developercommunity.visualstudio.com/t/Visual-Studio-linkexe-crashes-on-networ/10735424
# ("Visual Studio link.exe crashes on network filesystem").


#### Install the software (requires mintty.exe running as "Adminstrator"):
cd ms-nfs41-client/destdir/cygdrive/c/cygwin64/sbin
bash ./msnfs41client.bash install
# then reboot


#### Run nfs41 client:
** Run deamon:
(requires to modify "msnfs41client.bash")
cd ms-nfs41-client/destdir/cygdrive/c/cygwin64/sbin
bash ./msnfs41client.bash run_daemon

** mount home dir:
(requires to modify "msnfs41client.bash")
cd ms-nfs41-client/destdir/cygdrive/c/cygwin64/sbin
bash ./msnfs41client.bash mount_homedir



######## Manually building ms-nfs41-client using Cygwin:
** Required software:
- Visual Studio 19
- WDK for Windows 10, version 2004, from
  https://go.microsoft.com/fwlink/?linkid=2128854
- Cygwin >= 3.5.0

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
# then reboot

#### Run nfs41 client:
** Run deamon:
(requires to modify "msnfs41client.bash")
bash ../cygwin/devel/msnfs41client.bash run_daemon


** mount home dir:
(requires to modify "msnfs41client.bash")
bash ../cygwin/devel/msnfs41client.bash mount_homedir


######## Testing:
Seen tests/manual_testing.txt

#### ToDo:
- Makefile/script support for release blob generaetion, local test installation etc
- DocBook/XML based documentation
- Document how to get and build ksh93 for Cygwin
- Cygwin-specific binary release blob
- Document the usage of utils/mount_sshnfs/ and utils/sshnfs/
- Add test code for SID etc mapping

# EOF.
