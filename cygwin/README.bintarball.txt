###
### msnfs41client Cygwin binary tarball README
###

##
## WARNING: ALPHA VERSION, ONLY SUITABLE FOR BUG HUNTING!!
##


#
# 1. What is this ?
#
NFSv4.1 filesystem driver for Windows 10/11&Windows Server 2019


#
# 2. Features:
#
- Full NFSv4.1 protocol support

- idmapper (mapping usernames and uid/gid values between server and
    client)

- Support for custom ports (NFSv4 defaults to TCP port 2049, this
    client can use different ports per mount)

- Support for nfs://-URLs
    * Why ? nfs://-URLs are crossplatform, portable and Character-Encoding
      independent descriptions of NFSv4 server resources (exports).
    - including custom ports and raw IPv6 addresses
    - nfs://-URL conversion utility (/usr/bin/nfsurlconv) to convert
        URLs, including non-ASCII/Unicode characters in mount path

- Support ssh forwarding, e.g. mounting NFSv4 filesystems via ssh
    tunnel

- Support for long paths (up to 4096 bytes), no Windows MAXPATH limit

- Unicode support
    - File names can use any Unicode character supported by
      the NFS server's filesystem.
    - nfs://-URLs can be used to mount filesystems with non-ASCII
      characters in the mount path, independent of current locale.

- UNC paths
    - Mounting UNC paths without DOS driver letter
    - IPv6 support in UNC paths
    - /sbin/nfs_mount prints UNC paths in Win32+Cygwin formats
    - Cygwin bash+ksh93 support UNC paths, e.g.
      cd //derfwnb4966@2049/nfs4/bigdisk/mysqldb4/

- IPv6 support
    - IPv6 address within '[', ']'
      (will be converted to *.ipv6-literal.net)

- Windows ACLs <---> NFSv4 ACL translation
    - Win32 C:\Windows\system32\icacls.exe
    - Cygwin /usr/bin/setfacl+/usr/bin/getfacl
    - Windows Explorer ACL dialog

- Support for NFSv4 public mounts (i.e. use the NFSv4 public file handle
    lookup protocol via $ nfs_mount -o public ... #)

- SFU/Cygwin support, including:
    - uid/gid
    - Cygwin symlinks

- Custom primary group support
    - Supports primary group changes in the calling process/thread
      (via |SetTokenInformation(..., TokenPrimaryGroup,...)|), e.g.
      if the calling process/threads switches the primary group
      in its access token then the NFSv4.1 client will use that
      group as GID for file creation.
    - newgrp(1)/sg(1)-style "winsg" utilty to run cmd.exe with
      different primary group, e.g.
      $ winsg [-] -g group [-c command | /C command] #

- Software compatibility:
    - Any NFSv4.1 server (Linux, Solaris, Illumos, FreeBSD, nfs4j,
        ...)
    - All tools from Cygwin/MinGW
    - Visual Studio
    - VMware Workstation (can use VMs hosted on NFSv4.1 filesystem)


#
# 3. Requirements:
#
- Windows 10 (32bit or 64bit), Windows 11 or Windows Server 2019
- Cygwin:
    - Cygwin versions:
        - 64bit: >= 3.5.3 (or 3.6.x-devel)
        - 32bit: >= 3.3.6
    - Packages (required):
        cygwin
        cygwin-devel
        cygrunsrv
        cygutils
        cygutils-extra
        bash
        bzip2
        coreutils
        getent
        gdb
        grep
        hostname
        less
        libiconv
        libiconv2
        pax
        pbzip2
        procps-ng
        sed
        tar
        time
        util-linux
        wget
    - Packages (recommended):
        libnfs-utils (for /usr/bin/nfs-ls)
        make
        bmake
        git
        gcc-core
        gcc-g++
        clang
        mingw64-i686-clang
        mingw64-x86_64-clang
        dos2unix
        unzip
        bison
        cygport
        libiconv-devel

#
# 4. Download and install Cygwin (if not installed yet):
#
# Windows 32bit-vs.-64bit can be tested from Windows cmd.exe console:
# Run this command:
# ---- snip ----
echo %PROCESSOR_ARCHITECTURE%
# ---- snip ----
# If this returns "AMD64" then you have a Windows 64bit kernel, and
# if it returns "x86" then you have Windows 32bit kernel.
# If you get any other value then this is a (documentation) bug.

- Cygwin 64bit can be installed like this:
# ---- snip ----
# Install Cygwin 64bit on Windows 64bit with packages required by "ms-nfs41-client"
# (Windows NFSv4.1 client):
# 1. Create subdir
mkdir download
cd download
# 2. Get installer from https://cygwin.com/setup-x86_64.exe
curl --remote-name "https://www.cygwin.com/setup-x86_64.exe"
# 3. Run installer with these arguments:
setup-x86_64.exe -q --site "https://mirrors.kernel.org/sourceware/cygwin" -P cygwin,cygwin-devel,cygrunsrv,cygutils,cygutils-extra,bash,bzip2,coreutils,getent,gdb,grep,hostname,less,libiconv,libiconv2,pax,pbzip2,procps-ng,sed,tar,time,util-linux,wget,libnfs-utils,make,bmake,git,dos2unix,unzip
# ---- snip ----


- Cygwin 32bit can be installed like this:
# ---- snip ----
# Install Cygwin 32bit on Windows 32bit with packages required by "ms-nfs41-client"
# (Windows NFSv4.1 client):
# 1. Create subdir
mkdir download
cd download
# 2. Get installer from https://www.cygwin.com/setup-x86.exe
curl --remote-name "https://www.cygwin.com/setup-x86.exe"
# 3. Run installer with these arguments:
setup-x86.exe --allow-unsupported-windows -q --no-verify --site "http://ctm.crouchingtigerhiddenfruitbat.org/pub/cygwin/circa/2022/11/23/063457" -P cygwin,cygwin-devel,cygrunsrv,cygutils,cygutils-extra,bash,bzip2,coreutils,getent,gdb,grep,hostname,less,libiconv,libiconv2,pax,pbzip2,procps-ng,sed,tar,time,util-linux,wget,libnfs-utils,make,bmake,git,dos2unix,unzip
# ---- snip ----


#
# 5. Download "ms-nfs41-client" installation tarball:
#
# (from a Cygwin terminal)
$ mkdir -p ~/download
$ cd ~/download
$ wget 'http://www.nrubsig.org/people/gisburn/work/msnfs41client/releases/testing/${bintarball.base_filename}.tar.bz2'
$ openssl sha256 "${bintarball.base_filename}.tar.bz2"
SHA2-256(${bintarball.base_filename}.tar.bz2)= ${bintarball.archive_sha256hash}


#
# 6. Installation (as "Administrator"):
#
$ (cd / && tar -xf ~/download/${bintarball.base_filename}.tar.bz2 )
$ /sbin/msnfs41client install
<REBOOT>


#
# 7. Deinstallation:
#
$ (set -o xtrace ; cd / && tar -tf ~/download/${bintarball.base_filename}.tar.bz2 | while read i ; do [[ -f "$i" ]] && rm "$i" ; done)
<REBOOT>


#
# 8. Usage:
#

# Option a)
# * Start NFSv4 client daemon as Windows service (requires
# "Adminstrator" account):

$ sc start ms-nfs41-client-service

# * Notes:
# - requires "Adminstrator" account, and one nfsd client daemon is
#   used for all users on a machine.
# - The "ms-nfs41-client-service" service is installed by default as
#   "disabled" and therefore always requires a "manual" start (e.g.
#   $ sc start ms-nfs41-client-service #)
# - note that DOS devices are virtualised per LSA Logon, so each Logon
#   needs to do a separare nfs_mount.exe to mount a NFSv4 share.
#   The exception are mounts created by user "SYSTEM", such mounts
#   are available to all users/logons.
#   (see PsExec or function "su_system" in msnfs41client.bash how
#   to run a process as user "SYSTEM")
# - nfsd_debug.exe will run as user "SYSTEM", but will do user
#   impersonation for each request
# - stopping the service will NOT unmount filesystems, and due to a
#   bug a reboot is required to restart and mount any NFSv4
#   filesystems again

# * Administration:
# - Follow new log messages:
$ tail -f '/var/log/ms-nfs41-client-service.log'
# - Query service status:
$ sc queryex ms-nfs41-client-service
# - Query service config:
$ sc qc ms-nfs41-client-service
# - Start service automatically:
# (nfsd_debug.exe will be started automagically, but mounts are
# not restored):
$ sc config ms-nfs41-client-service start=auto
# - Start service manually (default):
$ sc config ms-nfs41-client-service start=disabled


# Option b)
# Run the NFSv4 client daemon manually:
#
# - run this preferably as "Administrator", but this is not a requirement
# - requires separate terminal
$ /sbin/msnfs41client run_daemon

# Mount a filesystem to drive N: and use it
$ /sbin/nfs_mount -o rw N 10.49.202.230:/net_tmpfs2
Successfully mounted '10.49.202.230@2049' to drive 'N:'
$ cd /cygdrive/n/
$ ls -la
total 4
drwxrwxrwt 5 Unix_User+0      Unix_Group+0      100 Dec  7 14:17 .
dr-xr-xr-x 1 roland_mainz     Kein                0 Dec 14 13:48 ..
drwxr-xr-x 3 Unix_User+197608 Unix_Group+197121  80 Dec 12 16:24 10492030
drwxr-xr-x 3 Unix_User+197608 Unix_Group+197121  60 Dec 13 17:58 directory_t
drwxr-xr-x 3 Unix_User+197608 Unix_Group+197121  60 Dec  7 11:01 test2

# Unmount filesystem:
$ cd ~ && /sbin/nfs_umount N:
# OR
$ cd ~
$ net use N: /delete

# Mount a filesystem WITHOUT a dos drive assigned and use it via UNC path
$ /sbin/nfs_mount -o rw 10.49.202.230:/net_tmpfs2
Successfully mounted '10.49.202.230@2049' to drive '\\10.49.202.230@2049\nfs4\net_tmpfs2'
$ cygpath -u '\\10.49.202.230@2049\nfs4\net_tmpfs2'
//10.49.202.230@2049/nfs4/net_tmpfs2
$ cd '//10.49.202.230@2049/nfs4/net_tmpfs2'
$ ls -la
total 4
drwxrwxrwt 5 Unix_User+0      Unix_Group+0      100 Dec  7 14:17 .
dr-xr-xr-x 1 roland_mainz     Kein                0 Dec 14 13:48 ..
drwxr-xr-x 3 Unix_User+197608 Unix_Group+197121  80 Dec 12 16:24 10492030
drwxr-xr-x 3 Unix_User+197608 Unix_Group+197121  60 Dec 13 17:58 directory_t
drwxr-xr-x 3 Unix_User+197608 Unix_Group+197121  60 Dec  7 11:01 test2

# Unmount filesystem:
$ cd ~ && /sbin/nfs_umount '\\10.49.202.230@2049\nfs4\net_tmpfs2'
# OR
$ cd ~
$ net use '\\10.49.202.230@2049\nfs4\net_tmpfs2' /delete

# List mounted NFSv4.1 filesystems:
$ /sbin/nfs_mount


# Global/System-wide mounts:
Mounts created by user "SYSTEM" are useable by all users in a system.
Example usage:
---- snip ----
# Create a file /etc/fstab.msnfs41client, which list the mounts
# which should be available system-wide
$ cat /etc/fstab.msnfs41client
nfs://[fe80::21b:1bff:fec3:7713]//bigdisk       V       nfs     rw      0       0
# run "ms-nfs41-client-globalmountall-service", which runs
# /sbin/mountall_msnfs41client as user "SYSTEM" to read
# /etc/fstab.msnfs41client and mount the matching filesystems
sc start ms-nfs41-client-globalmountall-service
---- snip ----

BUG: Note that "ms-nfs41-client-globalmountall-service" currently
does not wait until nfsd*.exe is available for accepting mounts.


#
# 9. Notes:
#

- Idmapping (including uid/gid mapping) between NFSv4 client and
  NFSv4 server works via /lib/msnfs41client/cygwin_idmapper.ksh,
  which either uses builtin static data, or /usr/bin/getent passwd
  and /usr/bin/getent group.
  As getent uses the configured name services it should work with
  LDAP too.
  This is still work-in-progress, with the goal that both NFSv4
  client and server can use different uid/gid numeric values for
  client and server side.

- UNC paths are supported, after successful mounting /sbin/nfs_mount
  will list the paths in Cygwin UNC format.

- SIDs work, users with valid Windows accounts (see Cygwin idmapping
  above get their SIDs, unknown users with valid uid/gid values get
  Unix_User+id/Unix_Group+id SIDs, and all others are mapped
  to nobody/nogroup SIDs.

- Workflow for nfs://-URLs:
  - Create nfs://-URLs with nfsurlconv, read $ nfsurlconv --man # for usage
  - pass URL to nfs_mount.exe like this:
    $ nfs_mount -o sec=sys,rw 'L' nfs://derfwnb4966_ipv4//bigdisk #

- Cygwin symlinks are supported, but might require
  $ fsutil behavior set SymlinkEvaluation L2L:1 R2R:1 L2R:1 R2L:1 #.
  This includes symlinks to UNC paths, e.g. as Admin
  $ cmd /c 'mklink /d c:\home\rmainz \\derfwpc5131_ipv6@2049\nfs4\export\home2\rmainz' #
  and then $ cd /cygdrive/c/home/rmainz/ # should work

- performance: All binaries are build without any optimisation, so
  the filesystem is much slower than it could be.

- bad performance due to Windows Defender AntiVirus:
  Option 1:
  # disable Windows defender realtime monitoring
  # (requires Admin shell)
  powershell -Command 'Set-MpPreference -DisableRealtimeMonitoring 1'
  Option 2:
  Add "nfsd.exe", "nfsd_debug.exe", "ksh93.exe", "bash.exe",
  "git.exe" and other offending commands to the process name
  whitelist.

- performance: Use vmxnet3 in VMware to improve performance

- ACLs are supported via the normal Windows ACL tools, but on
  Linux require the nfs4_getfacl/nfs4_setfacl utilities to see the
  data.
  * Example 1 (assuming that Windows, Linux NFSv4 client and NFSv4
  server have a user "siegfried_wulsch"):
  - On Windows on a NFSv4 filesystem:
  $ icacls myhorribledata.txt /grant "siegfried_wulsch:WD" #
  - On Linux NFSv4 clients you will then see this:
  # ---- snip ----
  $ nfs4_getfacl myhorribledata.txt
  A::OWNER@:rwatTcCy
  A::siegfried_wulsch@global.loc:rwatcy
  A::GROUP@:rtcy
  A::EVERYONE@:rtcy
  # ---- snip ----

  * Example 2 (assuming that Windows, Linux NFSv4 client and NFSv4
  server have a group "cygwingrp2"):
  - On Windows on a NFSv4 filesystem:
  $ icacls myhorribledata.txt /grant "cygwingrp2:(WDAC)" /t /c #
  - On Linux NFSv4 clients you will then see this:
  # ---- snip ----
  $ nfs4_getfacl myhorribledata.txt
  A::OWNER@:rwatTcCy
  A::GROUP@:rtcy
  A:g:cygwingrp2@global.loc:rtcy
  A::EVERYONE@:rtcy
  # ---- snip ----

- nfs_mount.exe vs. reserved ports:
  By default the NFSv4 server on Solaris, Illumos, Linux
  etc. only accepts connections if the NFSv4 client uses a
  "privileged (TCP) port", i.e. using a TCP port number < 1024.
  If nfsd.exe/nfsd_debug.exe is started without the Windows priviledge
  to use reserved ports, then a mount attempt can fail.
  This can be worked around on the NFSv4 server side - on Linux using
  the "insecure" export option in /etc/exports and on Solaris/Illumos
  using export option "resvport" (see nfs(5)).

- Accessing mounts from a VMware/QEMU/VirtualBox VM using NAT requires
  the the "insecure" export option in /etc/exports and on
  Solaris/Illumos using export option "resvport" (see nfs(5)), as the
  NFSv4 client source TCP port will be >= 1024.

- Install: Adding Windows accounts+groups to the NFSv4 server:
  ms-nfs41-client comes with /sbin/cygwinaccount2nfs4account to
  convert the Win32/Cygwin account information of the (current)
  user+groups to a small script for the NFSv4 server to set-up
  these accounts on the server side.

#
# 10. Known issues:
#
- The kernel driver ("nfs41_driver.sys") does not yet have a
  cryptographic signature for SecureBoot - which means it will only
  work if SecureBoot is turned off (otherwise
  $ /sbin/msnfs41client install # will FAIL!)

- If nfsd_debug.exe crashes or gets killed, the only safe way
  to run it again requires a reboot

- LDAP support does not work yet

- Attribute caching is too aggressive

- Caching in the kernel does not always work. For example
  $ tail -f ... # does not not see new data.
  Workaround: Use GNU tail'S $ tail --follow=name ... #
  Working theory is that this is related to FCB caching, see
  |FCB_STATE_FILESIZECACHEING_ENABLED|, as the nfs41_driver.sys
  kernel module does not see the |stat()| syscalls. But $ tail -f ... #
  always works for a momemnt if something else opens the same file.

- Unmounting and then mounting the same filesystem causes issues
  as the name cache in nfsd*.exe is not flushed on umount, including
  leftover delegations.

- krb5p security with AES keys do not work against the linux server,
  as it does not support gss krb5 v2 tokens with rotated data.

- When recovering opens and locks outside of the server's grace
  period, client does not check whether the file has been modified
  by another client.

- If nfsd.exe is restarted while a drive is mapped, that drive needs
  to be remounted before further use.

- Does not allow renaming a file on top of an existing open file.
  Connectathon's special test op_ren has been commented out.

- File access timestamps might be wrong for delegations.

- Extended attributes are supported with some limitations:
  a) the server must support NFS Named Attributes,
  b) the order of listings cannot be guaranteed by NFS, and
  c) the EaSize field cannot be reported for directory queries of
  FileBothDirInformation, FileFullDirInfo, or FileIdFullDirInfo.

- Win10/32bit-only: $ net use H: /delete # does not work,
  use $ nfs_umount 'H' instead #

- Bug: Subversion checkout can fail with
  "sqlite[S11]: database disk image is malformed" like this:
  # ---- snip ----
  $ svn --version
  svn, version 1.14.2 (r1899510)
    compiled May 20 2023, 11:51:30 on x86_64-pc-cygwin
  $ svn checkout https://svn.FreeBSD.org/base/head/share/man
  A    man/man4
  A    man/man4/tcp.4
  A    man/man4/ndis.4
  A    man/man4/Makefile
  A    man/man4/altq.4
  A    man/man4/miibus.4
  A    man/man4/vlan.4
  A    man/man4/ng_macfilter.4
  A    man/man4/mn.4
  A    man/man4/ossl.4
  A    man/man4/ktls.4
  A    man/man4/ftwd.4
  A    man/man4/inet6.4
  A    man/man4/crypto.4
  A    man/man4/rtsx.4
  A    man/man4/isp.4
  svn: E200030: sqlite[S11]: database disk image is malformed
  svn: E200042: Additional errors:
  svn: E200030: sqlite[S11]: database disk image is malformed
  svn: E200030: sqlite[S11]: database disk image is malformed
  svn: E200030: sqlite[S11]: database disk image is malformed
  # ---- snip ----
  Workaround is to mount the NFS filesystem with the "writethru"
  option, e.g.
  $ /sbin/nfs_mount -o rw,writethru 'j' derfwpc5131:/export/home/rmainz #

- Windows event log can list errors like "MUP 0xc0000222"
  (|STATUS_LOST_WRITEBEHIND_DATA|) in case the disk on the NFSv4 server
  is full and outstanding writes from a memory-mapped file fail.
  Example:
  ---- snip ----
  {Fehler beim verzoegerten Schreibvorgang} Nicht alle Daten fuer die
  Datei "\\34.159.25.153@2049\nfs4\export\nfs4export\gcc\lto-dump.exe"
  konnten gespeichert werden. Daten gingen verloren.
  Dieser Fehler wurde von dem Server zurueckgegeben, auf dem sich die
  Datei befindet. Versuchen Sie, die Datei woanders zu speichern.
  ---- snip ----

- Bug: Native Windows git (NOT cygwin /usr/bin/git) clone fails
  like this:
  # ---- snip ----
  $ '/cygdrive/c/Program Files/Git/cmd/git' --version
  git version 2.45.2.windows.1
  $ '/cygdrive/c/Program Files/Git/cmd/git' clone https://github.com/kofemann/ms-nfs41-client.git
  Cloning into 'ms-nfs41-client'...
  remote: Enumerating objects: 6558, done.
  remote: Counting objects: 100% (318/318), done.
  remote: Compressing objects: 100% (172/172), done.
  remote: Total 6558 (delta 191), reused 233 (delta 141), pack-reused 6240 (from 1)
  Receiving objects: 100% (6558/6558), 2.43 MiB | 4.66 MiB/s, done.
  fatal: premature end of pack file, 655 bytes missing
  warning: die() called many times. Recursion error or racy threaded death!
  fatal: fetch-pack: invalid index-pack output
  # ---- snip ----
  Workaround is to mount the NFS filesystem with the "writethru"
  OR "nocache" option, e.g.
  $ /sbin/nfs_mount -o rw,writethru 'j' derfwpc5131:/export/home/rmainz #

#
# 11. Notes for troubleshooting && finding bugs/debugging:
#
- nfsd_debug.exe has the -d option to set a level for debug
  output.
  Edit /sbin/msnfs41client to set the "-d" option.

- The "msnfs41client" script has the option "watch_kernel_debuglog"
  to get the debug output of the kernel module.

  Run as Admin: $ /sbin/msnfs41client watch_kernel_debuglog #

  Currently requires DebugView
  (https://learn.microsoft.com/en-gb/sysinternals/downloads/debugview)
  to be installed.

- Watching network traffic:
  WireShark has a command line tool called "tshark", which can be used
  to see NFSv4 traffic. As NFSv4 uses RPC you have to filter for RPC,
  and the RPC filter automatically identifies NFSv4 traffic on it's RPC
  id.
  Example for Windows:
  (for NFSv4 default TCP port "2049", replace "2049" with the
  desired port if you use a custom port ; use "ipconfig" to find the
  correct interface name, in this case "Ethernet0"):
  # ---- snip ----
  $ nfsv4port=2049 ; /cygdrive/c/Program\ Files/Wireshark/tshark \
    -f "port $nfsv4port" -d "tcp.port==${nfsv4port},rpc" -i Ethernet0
  # ---- snip ----

  If you are running inside a VMware VM on a Linux host it
  might require $ chmod a+rw /dev/vmnet0 # on VMware host, so that
  the VM can use "Promiscuous Mode".


#
# 12. Source code:
#
- Source code can be obtained from https://github.com/kofemann/ms-nfs41-client

- Build instructions can be found at
https://github.com/kofemann/ms-nfs41-client/tree/master/cygwin


# EOF.
