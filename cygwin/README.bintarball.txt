###
### msnfs41client Cygwin binary tarball README
###

##
## WARNING: ALPHA VERSION, ONLY SUITABLE FOR BUG HUNTING!!
##

##
## Installation/Deinstallation
##

# 1. Requirements:
- Windows 10
- Cygwin 3.5.0
    - Packages:
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
        pax
        pbzip2
        procps-ng
        sed
        tar
        time
        util-linux
        wget


# 2. Installation (as "Administrator"):
$ mkdir -p ~/download
$ cd ~/download
$ wget 'http://www.nrubsig.org/people/gisburn/work/msnfs41client/releases/alpha/msnfs41client_cygwin_binaries_git148e927_20231214_12h31m.tar.bz2'
$ (cd / && tar -xf ~/download/msnfs41client_cygwin_binaries_git148e927_20231214_12h31m.tar.bz2 )
$ /sbin/msnfs41client install


# 3. Deinstallation:
$ (set -x ; cd / && tar -tf ~/download/msnfs41client_cygwin_binaries_git148e927_20231214_12h31m.tar.bz2 | while read i ; do [[ -f "$i" ]] && rm "$i" ; done)


##
## Usage
##

# Run the NFSv4 client daemon:
# - run this preferably as "Administrator", but this is not a requirement
# - requires separate terminal
$ /sbin/msnfs41client run_daemon

# Mount a filesystem and use it
# - requires that NFSv4 server accepts connections from a TCP port
# number > 1024, which can be archived on Linux with the "insecure"
# export option in /etc/exports, or "resvport" on Solaris/Illumos
# (see nfs(5))
$ /sbin/nfs_mount -o rw N 10.49.20.110:/net_tmpfs2
Successfully mounted '10.49.20.110@2049' to drive 'N:'
$ cd /cygdrive/n/
$ ls -la
total 4
drwxrwxrwt 5 Unix_User+0      Unix_Group+0      100 Dec  7 14:17 .
dr-xr-xr-x 1 roland_mainz     Kein                0 Dec 14 13:48 ..
drwxr-xr-x 3 Unix_User+197608 Unix_Group+197121  80 Dec 12 16:24 10492030
drwxr-xr-x 3 Unix_User+197608 Unix_Group+197121  60 Dec 13 17:58 directory_t
drwxr-xr-x 3 Unix_User+197608 Unix_Group+197121  60 Dec  7 11:01 test2

# Unmount filesystem:
$ cd ~ && /sbin/nfs_mount -d N:
# OR
$ cd ~
$ net use N: /delete


#
# Notes:
#
- Idmapping (including uid/gid mapping) between NFSv4 client and NFSv4
  server works via /lib/msnfs41client/cygwin_idmapper.ksh, which
  either uses builtin static data, or /usr/bin/getent passwd and
  /usr/bin/getent group.
  As getent uses the configured name services it should work with LDAP
  too.
  This is still work-in-progress, with the goal that both NFSv4 client
  and server can use different uid/gid numeric values for client and
  server side.

- UNC paths are supported, after successful mounting /sbin/nfs_mount
  will list the paths in Cygwin UNC format.

- SIDs work, users with valid Windows accounts (see Cygwin idmapping
  above get their SIDs, unknown users with valid uid/gid values get
  Unix_User+id/Unix_Group+id SIDs, and all others are mapped
  to nobody/nogroup SIDs.

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
  Add "nfsd.exe", "nfsd_debug.exe", "ksh93.exe", "bash.exe", "git.exe"
  and other offending commands to the process name whitelist.

- performance: Use vmxnet3 in VMware to improve performance

- ACLs are supported via the normal Windows ACL tools, but on
  Linux require the nfs4_getfacl/nfs4_setfacl utilities to see the
  data.
  Example (assuming that Windows, Linux NFSv4 client and NFSv4
  server have a user "siegfried_wulsch"):
  - On Windows on a NFSv4 filesystem, :
  $ icacls myhorribledata.txt /grant "siegfried_wulsch:WD" #
  - On Linux NFSv4 clients you will then see this:
  ---- snip ----
  $ nfs4_getfacl myhorribledata.txt
  A::OWNER@:rwatTcCy
  A::siegfried_wulsch@global.loc:rwatcy
  A::GROUP@:rtcy
  A::EVERYONE@:rtcy
  ---- snip ----

- nfs_mount only works when the NFSv4 server allows connections from
  ports >= 1024, as Windows does not allow the Windows NFSv4 client
  to use a "privileged port" (i.e. TCP port number < 1024)).
  By default the NFSv4 server on Solaris, Illumos, Linux
  etc. only accepts connections if the NFSv4 client uses a "privileged
  (TCP) port", i.e. a port number < 1024.
  This can be worked around by using the "insecure" export option in
  Linux /etc/exports, which allows connections from ports >= 1024,
  and for Solaris/Illumos see nfs(5), option "resvport".

#
# Known issues:
#
- The kernel driver ("nfs41_driver.sys") does not have a cryptographic
  signature for SecureBoot - which means it will only work if SecureBoot
  is turned off (otherwise $ /sbin/msnfs41client install # will FAIL!)
- If nfsd_debug.exe crashes or gets killed, the only safe way
  to run it again requires a reboot
- LDAP support does not work yet
- Attribute caching is too aggressive, making $ tail -f ... # not seeing
  new data.
  Workaround: Use GNU tail'S $ tail --follow=name ... #
- krb5p security with AES keys do not work against the linux server,
  as it does not support gss krb5 v2 tokens with rotated data.
- When recovering opens and locks outside of the server's grace period,
  client does not check whether the file has been modified by another
  client.
- If nfsd.exe is restarted while a drive is mapped, that drive needs
  to be remounted before further use.
- Does not allow renaming a file on top of an existing open file.
  Connectathon's special test op_ren has been commented out.
- Extended attributes are supported with some limitations:
  a) the server must support NFS Named Attributes,
  b) the order of listings cannot be guaranteed by NFS, and
  c) the EaSize field cannot be reported for directory queries of
  FileBothDirInformation, FileFullDirInfo, or FileIdFullDirInfo.

# EOF.
