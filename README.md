---
title: Windows NFS 4.2 FileSystem Client Instructions
---

- [What is this ?](#what-is-this)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Download and install Cygwin (if not installed
    yet)](#download-install-cygwin)
  - [Download and install MSYS2/64bit
    \[OPTIONAL\]](#download-install-msys2)
  - [Download "ms-nfs41-client" installation
    tarball](#download-msnfs41client-tarball)
  - [Installation (as "Administrator")](#installation-via-cygwin)
  - [Deinstallation](#deinstallation)
- [Usage](#usage)
  - [Preparing the NFS server](#prep_nfs_server)
    - [NFS server config](#nfs_server_config)
    - [User/group accounts on the NFS server](#nfs_server_accounts)
  - [Starting the NFS client daemon](#starting_nfs_daemon)
    - [Run as Windows Service](#run_as_windows_service)
    - [Manual starting the daemon](#manual_start)
  - [Mounting and using NFS filesystems](#mounting_and_using)
    - [Basic usage](#basic_usage)
    - [Global/System-wide mounts](#global-system-wide-mounts)
    - [WSL usage](#wsl-usage)
- [Notes](#notes)
- [Known issues](#known-issues)
- [Troubleshooting && finding
  bugs/debugging](#troubleshooting-debugging)
- [Development](#development)
  - [Source code](#source-code)
  - [Building ms-nfs41-client](#building_msnfs41client)
    - [Building ms-nfs41-client using
      Cygwin+Makefile](#building-cygwin-makefile)
    - [Testing](#testing)
- [Mailing list](#mailinglist)

# What is this ?

NFSv4.2/NFSv4.1 filesystem driver for Windows 10/11 & Windows Server
2019+2022+2025

# Features

- Full NFSv4.2/NFSv4.1 protocol support

- idmapper (mapping usernames and uid/gid values between server and
  client)

- Support for custom ports (NFSv4 defaults to TCP port 2049, this client
  can use different ports per mount)

- Support for `nfs://`-URLs

  - Why? `nfs://`-URLs are cross-platform, portable and
    Character-Encoding independent descriptions of NFSv4 server
    resources (exports).

  - including custom ports and raw IPv6 addresses

  - `nfs://`-URL conversion utility (`/usr/bin/nfsurlconv`) to convert
    URLs, including non-ASCII/Unicode characters in mount path

- Support ssh forwarding, e.g., mounting NFSv4 filesystems via ssh
  tunnel

- Support for long paths (up to 4096 bytes), no Windows MAXPATH limit

- Unicode support

  - File names can use any Unicode character supported by the NFS
    server's filesystem.

  - `nfs://`-URLs can be used to mount filesystems with non-ASCII
    characters in the mount path, independent of current locale.

- UNC paths

  - Mounting UNC paths without DOS drive letter

  - IPv6 support in UNC paths

  - `/sbin/nfs_mount` prints UNC paths in Win32+Cygwin/MSYS2 formats

  - Cygwin/MSYS2 bash+ksh93 support UNC paths, e.g.,
    `cd //derfwnb4966@NFS@2049/bigdisk/mysqldb4/`

  - Symlinks on NFS can redirect to other filesystems via UNC syntax and
    work with Cygwin, MSYS2, cmd.exe, powershell etc., e.g.:

        mklink /D symlnk1_to_h_tmp \\lab17@NFS@2049\export\home\rsm\tmp

- WSL support

  - Mount Windows NFSv4.2 shares via drive letter or UNC path in WSL via
    `mount -t drvfs`

  - Supports NFS owner/group to WSL uid/gid mapping

- IPv6 support

  - IPv6 address within '\[', '\]' (will be converted to
    \*.ipv6-literal.net)

- Windows ACLs \<---\> NFSv4 ACL translation

  - Win32 `C:\Windows\system32\icacls.exe`

  - Cygwin `/usr/bin/setfacl`+`/usr/bin/getfacl`

  - Windows Explorer ACL dialog

- Sparse file support

  - Requires NFSv4.2 server which supports the NFSv4.2 operations
    "ALLOCATE", "DEALLOCATE", "SEEK", and the
    `|FATTR4_WORD1_SPACE_USED|` attribute.

  - Full Win32 sparse file API support, including creation, punching
    holes, enumeration of hole&data ranges etc.

  - Supports Win32 APIs `|FSCTL_QUERY_ALLOCATED_RANGES|`,
    `|FSCTL_SET_SPARSE|`, `|FSCTL_SET_ZERO_DATA|`; and
    `|NfsV3Attributes.used|` EA

  - Cygwin sparse file support requires \>= Cygwin 3.6 to support
    POSIX-1.2024 `|lseek(...,SEEK_HOLE/SEEK_DATA,...)|`, which is needed
    for coreutils `/usr/bin/fallocate` and
    `$ /usr/bin/cp --sparse=auto src dest #`

  - `/cygdrive/c/Windows/system32/fsutil sparse queryrange myfile.dat`
    can be used to enumerate ranges where data are allocated (BUG:
    Win10+Win11 fsutil only support 64 data ranges, the filesystem
    itself supports an unlimited number of data ranges)

  - `/cygdrive/c/Windows/system32/xcopy /sparse` can be used to copy
    sparse files. Requires on Win11 \>= 22H2 because it relies on
    `|CopyFile2()|` flag `|COPY_FILE_ENABLE_SPARSE_COPY|`.

- Case-insensitive filesystem support

  - Requires NFSv4.1 server which supports the
    `|FATTR4_WORD0_CASE_INSENSITIVE|` attribute set to `TRUE` (currently
    Windows Server NFSv4.1 server exporting NTFS).

- Data copy offload (server-side copy)

  - Implemented via Win32 `|FSCTL_OFFLOAD_READ|`+`|FSCTL_OFFLOAD_WRITE|`
    to copy data blocks directly on the server.

  - Requires NFSv4.2 server which supports the NFSv4.2 operations
    "COPY", "DEALLOCATE", "SEEK"

  - Sparse files are correctly copied including all hole and data ranges

  - Windows 10 `|CopyFile2()|` API uses
    `|FSCTL_OFFLOAD_READ|`+`|FSCTL_OFFLOAD_WRITE|` by default

  - Windows 10 tools like xcopy.exe (on Windows 11 requires `/NOCLONE`,
    otherwise block cloning is the default), robocopy etc. all use
    `|CopyFile2()|`, and therefore server-side copies by default

- Block cloning support

  - Implemented via Win32 `|FSCTL_DUPLICATE_EXTENTS_TO_FILE|` to clone
    file blocks from src to dst within the same filesystem.

  - Requires NFSv4.2 server which supports the NFSv4.2 operations
    "CLONE", "DEALLOCATE", "SEEK", and exports a filesystem which
    supports block cloning (e.g. Linux BTRFS+XFS, but NOT Linux tmpfs)

  - Sparse files are correctly cloned, including all hole and data
    ranges

  - `/usr/bin/winclonefile.exe` can be used to clone a file

  - Windows 11 `|CopyFile2()|` API uses
    `|FSCTL_DUPLICATE_EXTENTS_TO_FILE|` by default

  - Windows 11 tools like xcopy.exe, robocopy etc. all use
    `|CopyFile2()|`, and therefore file cloning by default

- Symlink reparse and translation support

  - Translates Win32/NT symlink syntax (e.g.
    `$ mklink /D ... Y:\tmp\ #`) to NFS/POSIX syntax (e.g.
    "`/cygdrive/y/tmp/`") and back

  - Translates Cygwin `/cygdrive/<devletter>` symlinks on NFS to Win32
    `<devletter>:\` and back

  - Pass-through for NFS `/dev-Symlinks` (e.g. `/dev/null`) to Cygwin

  - Interoperability for symlinks between Cygwin, powershell, cmd.exe
    and other POSIX-compatible NFSv4.2/NFSv4.1 clients.

- Support for NFSv4 public mounts (i.e., use the NFSv4 public file
  handle lookup protocol via
  `$ nfs_mount -o public ... relative-path-or-url#`)

- Support for NFSv4 referrals

  - See Linux `export(5) refer=` option, `nfsref(5)` or
    <https://docs.oracle.com/cd/E86824_01/html/E54764/nfsref-1m.html>

- SFU/Cygwin/MSYS2 support, including:

  - POSIX uid/gid+mode

  - Backwards compatibility to Microsoft's NFSv3 driver

  - Cygwin ACLs, e.g., `setfacl`/`getfacl`

  - Cygwin/MSYS2 symlinks

- Custom primary group support

  - Supports primary group changes in the calling process/thread (via
    `|SetTokenInformation(..., TokenPrimaryGroup,...)|`), e.g., if the
    calling process/threads switches the primary group in its access
    token then the NFSv4.2 client will use that group as GID for file
    creation.

  - `newgrp(1)`/`sg(1)`-style "winsg" utility to run cmd.exe with
    different primary group, e.g.,
    `$ winsg [-] -g group [-c command | /C command] #`

- Software compatibility:

  - Any NFSv4.2/NFSv4.1 server (Linux, Solaris, Illumos, FreeBSD, nfs4j,
    ...)

  - All tools from Cygwin/MSYS2/MinGW

  - Visual Studio (tested: VS2019 Community VS2022 Community, VS2026
    Community Insiders)

  - VMware Workstation (can use VMs hosted on NFSv4.2/NFSv4.1
    filesystem)

  - MariaDB (including sparse file support for [page
    compression](https://dev.mysql.com/doc/refman/8.4/en/innodb-page-compression.html))

  - Microsoft Office (tested: Office 2016)

  - Windows 16bit DOS and Windows 3.x applications via [NT Virtual DOS
    Machine](https://learn.microsoft.com/en-us/windows/compatibility/ntvdm-and-16-bit-app-support)
    (requires case-insensitive filesystem), e.g. [Borland Turbo C
    compiler](https://web.archive.org/web/20040401174842/http://bdn.borland.com/article/0,1410,20841,00.html),
    [Total Commander for Windows
    3.x](https://www.ghisler.com/wcmd16.htm),
    [DOSNIX](http://www.retroarchive.org/garbo/pc/unix/dosnx23b.zip),
    [DOS 16bit
    zip](https://github.com/DankRank/ftp.info-zip.org/raw/refs/heads/master/ftp.info-zip.org/pub/infozip/msdos/zip232x.zip),
    ...

  - ...

# Requirements

- Windows 10 (32bit or 64bit), Windows 11 or Windows Server
  2019+2022+2025

- Cygwin:

  - Cygwin versions:

    - 64bit: \>= 3.5.7, recommended \>= 3.6.1

    - 32bit: \>= 3.3.6

  - Packages (required): `cygwin`, `cygrunsrv`, `cygutils`,
    `cygutils-extra`, `libiconv`, `libiconv2`, `procps-ng`, `util-linux`

  - Packages (optional, recommended, required to build ms-nfs41-client):
    `bison`, `cygport`, `cygwin-devel`, `clang`, `dos2unix`, `pax`,
    `pbzip2`, `libnfs-utils` (for `/usr/bin/nfs-ls`), `libiconv-devel`,
    `make`, `bmake`, `git`, `gcc-core`, `gcc-g++`, `gdb`,
    `mingw64-i686-clang`, `mingw64-x86_64-clang`, `unzip`, `time`,
    `docbook-utils`, `docbook-xml45`, `docbook-xsl`, `docbook-xsl-ns`,
    `libxslt`, `w3m`

  - Packages (only-CI):

    \# required packages, but part of Cygwin default installation,
    listed here for CI package list ONLY

    `bash`, `bzip2`, `coreutils`, `getent`, `grep`, `hostname`, `less`,
    `sed`, `tar`, `wget`

- MSYS2 (64bit, optional):

  - Packages (recommended): `base-devel`, `gcc`, `clang`, `sed`, `time`,
    `coreutils`, `util-linux`, `grep`, `sed`, `emacs`, `gdb`, `make`,
    `autoconf`, `automake`, `gettext`, `gettext-devel`, `git`,
    `subversion`, `flex`, `bison`, `unzip`, `pax`, `tar`,
    `libiconv-devel`, `ncurses-devel`, `gmp-devel`, `mpfr-devel`,
    `mpc-devel`, `isl-devel`, `procps-ng`, `libiconv-devel`

# Installation

## Download and install Cygwin (if not installed yet)

Windows 32bit-vs.-64bit can be tested from Windows `cmd.exe` console:

Run this command:

    echo %PROCESSOR_ARCHITECTURE%

If this returns "AMD64" then you have a Windows 64bit kernel, and if it
returns "x86" then you have Windows 32bit kernel. If you get any other
value then this is a (documentation) bug.

Cygwin 64bit can be installed like this:

**Install Cygwin 64bit on Windows 64bit with packages required by
"ms-nfs41-client" (Windows NFSv4.2 client):**

1.  Create subdir

        mkdir download
        cd download

2.  Get installer from <https://cygwin.com/setup-x86_64.exe>

        curl --remote-name "https://www.cygwin.com/setup-x86_64.exe"

3.  Run installer with these arguments:

        setup-x86_64.exe -q --site "https://mirrors.kernel.org/sourceware/cygwin" -P cygwin,cygwin-devel,cygrunsrv,cygutils,cygutils-extra,bash,bzip2,coreutils,getent,gdb,grep,hostname,less,libiconv,libiconv2,pax,pbzip2,procps-ng,sed,tar,time,util-linux,wget,libnfs-utils,make,bmake,git,dos2unix,unzip

Cygwin 32bit can be installed like this:

**Install Cygwin 32bit on Windows 32bit with packages required by
"ms-nfs41-client" (Windows NFSv4.2 client):**

1.  Create subdir

        mkdir download
        cd download

2.  Get installer from <https://www.cygwin.com/setup-x86.exe>

        curl --remote-name "https://www.cygwin.com/setup-x86.exe"

3.  Run installer with these arguments:

        setup-x86.exe --allow-unsupported-windows -q --no-verify --site "http://ctm.crouchingtigerhiddenfruitbat.org/pub/cygwin/circa/2022/11/23/063457" -P cygwin,cygwin-devel,cygrunsrv,cygutils,cygutils-extra,bash,bzip2,coreutils,getent,gdb,grep,hostname,less,libiconv,libiconv2,pax,pbzip2,procps-ng,sed,tar,time,util-linux,wget,libnfs-utils,make,git,dos2unix,unzip

## Download and install MSYS2/64bit \[OPTIONAL\]

1.  Download & install from Cygwin

        mkdir -p download && cd download
        # ARM64: https://github.com/msys2/msys2-installer/releases/download/2025-08-30/msys2-arm64-20250830.exe
        # x86_64: https://github.com/msys2/msys2-installer/releases/download/2025-08-30/msys2-x86_64-20250830.exe
        wget 'https://github.com/msys2/msys2-installer/releases/download/2025-08-30/msys2-x86_64-20250830.exe'
        chmod a+x 'msys2-x86_64-20250830.exe'
        ./msys2-x86_64-20250830 --default-answer --root 'C:\msys64' install

2.  Install extra packages:

    Start MSYS2 UCRT mintty and execute this:

        pacman -S --noconfirm base-devel gcc clang sed time coreutils util-linux grep sed emacs gdb make autoconf automake gettext gettext-devel git subversion flex bison unzip pax tar libiconv-devel ncurses-devel gmp-devel mpfr-devel mpc-devel isl-devel procps-ng libiconv-devel

> [!NOTE]
> NFS filesystem used the MSYS root filesystem must be mounted as global
> filesystem
>
> <div>
>
> <div class="title">
>
> Known issues
>
> </div>
>
> 1.  Edit `/etc/pacman.conf` and set
>
>         SigLevel = Never
>
>     , because due to a Cygwin/MSYS2 bug there is a mismatch between
>     Cygwin/MSYS2 POSIX uid/gid and Win32 owner/owner_group SIDs
>
> 2.  Permissions of the `/tmp` dir should be fixed:
>
>         chmod a+rwxt /tmp
>
> </div>

## Download "ms-nfs41-client" installation tarball

(from a Cygwin terminal)

    $ mkdir -p ~/download
    $ cd ~/download
    $ wget 'http://www.nrubsig.org/people/gisburn/work/msnfs41client/releases/testing/${bintarball.base_filename}.tar.bz2'
    $ openssl sha256 "${bintarball.base_filename}.tar.bz2"
    SHA2-256(${bintarball.base_filename}.tar.bz2)= ${bintarball.archive_sha256hash}

## Installation (as "Administrator")

    $ (cd / && tar -xf ~/download/${bintarball.base_filename}.tar.bz2 )
    $ /sbin/msnfs41client install
    <REBOOT>

## Deinstallation

    $ (set -o xtrace ; cd / && tar -tf ~/download/${bintarball.base_filename}.tar.bz2 | while read i ; do [[ -f "$i" ]] && rm "$i" ; done)
    <REBOOT>

# Usage

## Preparing the NFS server

### NFS server config

- Make sure the NFS client can access the NFS server

- The NFS server should send owner and owner_group information as
  user@domain and group@domain, and not as numeric uid/gid information

### User/group accounts on the NFS server

It is required that all Windows users and groups used by the Windows NFS
client have user/group accounts on the server side.

If no central user&group management between NFS server and NFS clients
exists the `/sbin/cygwinaccount2nfs4account` script can be used to
manually create matching `/etc/group` and `/etc/passwd` entries on the
NFS server side.

## Starting the NFS client daemon

### Run as Windows Service

- Start NFSv4 client daemon as Windows service (requires "Administrator"
  account):

      $ sc start ms-nfs41-client-service

- Notes:

  - requires "Administrator" account, and one nfsd client daemon is used
    for all users on a machine.

  - The "ms-nfs41-client-service" service is installed by default as
    "enabled" and therefore does not require a "manual" start (e.g.,
    `$ sc start ms-nfs41-client-service #`)

  - DOS devices are virtualised per LSA Logon, so each Logon needs to do
    a separate `nfs_mount.exe` to mount a NFSv4 share. The exception are
    mounts created by user "SYSTEM", such mounts are available to all
    users/logons. (see `PsExec` or function "su_system" in
    `msnfs41client.bash` how to run a process as user "SYSTEM")

  - `nfsd_debug.exe` will run as user "SYSTEM", but will do user
    impersonation for each request

  - stopping the service will NOT unmount filesystems, and due to a bug
    a reboot is required to restart and mount any NFSv4 filesystems
    again

- Administration:

  - Follow new log messages:

        $ tail -f '/var/log/ms-nfs41-client-service.log'

  - Query service status:

        $ sc queryex ms-nfs41-client-service

  - Query service config:

        $ sc qc ms-nfs41-client-service

  - Start service automatically (default):

    (`nfsd_debug.exe` will be started automagically, but mounts are not
    restored):

        $ /sbin/msnfs41client enableautostartservices

  - Start service manually:

        $ /sbin/msnfs41client disableautostartservices

### Manual starting the daemon

Run the NFSv4 client daemon manually:

- run this preferably as "Administrator", but this is not a requirement

- requires separate terminal

<!-- -->

    $ /sbin/msnfs41client run_daemon

## Mounting and using NFS filesystems

### Basic usage

Mount a filesystem to drive N: and use it

    $ /sbin/nfs_mount -o rw N 10.49.202.230:/net_tmpfs2
    Successfully mounted '10.49.202.230@NFS@2049' to drive 'N:'
    $ cd /cygdrive/n/
    $ ls -la
    total 4
    drwxrwxrwt 5 Unix_User+0      Unix_Group+0      100 Dec  7 14:17 .
    dr-xr-xr-x 1 roland_mainz     Kein                0 Dec 14 13:48 ..
    drwxr-xr-x 3 Unix_User+197608 Unix_Group+197121  80 Dec 12 16:24 10492030
    drwxr-xr-x 3 Unix_User+197608 Unix_Group+197121  60 Dec 13 17:58 directory_t
    drwxr-xr-x 3 Unix_User+197608 Unix_Group+197121  60 Dec  7 11:01 test2

Unmount filesystem:

    $ cd ~ && /sbin/nfs_umount N:
    # OR
    $ cd ~
    $ net use N: /delete

Mount a filesystem WITHOUT a dos drive assigned and use it via UNC path

    $ /sbin/nfs_mount -o rw 10.49.202.230:/net_tmpfs2
    Successfully mounted '10.49.202.230@NFS@2049' to drive '\\10.49.202.230@NFS@2049\net_tmpfs2'
    $ cygpath -u '\\10.49.202.230@NFS@2049\net_tmpfs2'
    //10.49.202.230@NFS@2049/net_tmpfs2
    $ cd '//10.49.202.230@NFS@2049/net_tmpfs2'
    $ ls -la
    total 4
    drwxrwxrwt 5 Unix_User+0      Unix_Group+0      100 Dec  7 14:17 .
    dr-xr-xr-x 1 roland_mainz     Kein                0 Dec 14 13:48 ..
    drwxr-xr-x 3 Unix_User+197608 Unix_Group+197121  80 Dec 12 16:24 10492030
    drwxr-xr-x 3 Unix_User+197608 Unix_Group+197121  60 Dec 13 17:58 directory_t
    drwxr-xr-x 3 Unix_User+197608 Unix_Group+197121  60 Dec  7 11:01 test2

Unmount filesystem:

    $ cd ~ && /sbin/nfs_umount '\\10.49.202.230@NFS@2049\net_tmpfs2'
    # OR
    $ cd ~
    $ net use '\\10.49.202.230@NFS@2049\net_tmpfs2' /delete

List mounted NFSv4.2 filesystems:

    $ /sbin/nfs_mount

### Global/System-wide mounts

Mounts created by user "SYSTEM" are usable by all users in a system.
Such mounts can be created by the `/sbin/nfs_globalmount` command, or
adding an entry in `/etc/fstab.msnfs41client`.

Example usage for `/etc/fstab.msnfs41client`:

    # Create a file /etc/fstab.msnfs41client, which list the mounts
    # which should be mounted system-wide at boot
    $ cat /etc/fstab.msnfs41client
    nfs://[fe80::21b:1bff:fec3:7713]//bigdisk       N:       nfs     sec=sys,rw      0       0
    # run "ms-nfs41-client-globalmountall-service", which runs
    # /sbin/mountall_msnfs41client as user "SYSTEM" to read
    # /etc/fstab.msnfs41client and mount the matching filesystems
    sc start ms-nfs41-client-globalmountall-service

### WSL usage

Example 1: Mount Windows NFSv4.2 share via Windows drive letter

Mount NFSv4.2 share in Windows to drive letter 'N':

    $ /sbin/nfs_mount -o rw 'N' nfs://10.49.202.230//bigdisk
    Successfully mounted '10.49.202.230@NFS@2049' to drive 'N:'

Within WSL mount drive letter 'N' to `/mnt/n`

    $ sudo bash
    $ mkdir /mnt/n
    $ mount -t drvfs N: /mnt/n

Example 2: Mount Windows NFSv4.2 share via UNC path:

Mount NFSv4.2 share in Windows

    $ /sbin/nfs_mount -o rw nfs://10.49.202.230//bigdisk
    Successfully mounted '10.49.202.230@NFS@2049' to drive '\\10.49.202.230@NFS@2049\bigdisk'

Within WSL mount UNC path returned by `/sbin/nfs_mount`

    $ sudo bash
    $ mkdir /mnt/bigdisk
    $ mount -t drvfs '\\10.49.202.230@NFS@2049\bigdisk' /mnt/bigdisk

**Known issues with WSL:**

- Softlinks do not work yet

- Creating a hard link returns "Invalid Argument", maybe drvfs
  limitation

- Not all POSIX file types (e.g. block devices) etc. are supported

# Notes

- Idmapping (including uid/gid mapping) between NFSv4 client and NFSv4
  server works via `/lib/msnfs41client/cygwin_idmapper.ksh`, which
  either uses builtin static data, or `/usr/bin/getent passwd` and
  `/usr/bin/getent group`. As `getent` uses the configured name services
  it should work with LDAP too. This is still work-in-progress, with the
  goal that both NFSv4 client and server can use different uid/gid
  numeric values for client and server side.

- UNC paths are supported, after successful mounting `/sbin/nfs_mount`
  will list the paths in Cygwin/MSYS2 UNC format.

- SIDs work, users with valid Windows accounts (see Cygwin idmapping
  above get their SIDs, unknown users with valid uid/gid values get
  Unix_User+id/Unix_Group+id SIDs, and all others are mapped to
  nobody/nogroup SIDs.

- Workflow for `nfs://`-URLs:

  - Create `nfs://`-URLs with `nfsurlconv`, read `$ nfsurlconv --man #`
    for usage

  - pass URL to `nfs_mount.exe` like this:
    `$ nfs_mount -o sec=sys,rw 'L' nfs://derfwnb4966_ipv4//bigdisk #`

- Cygwin/MSYS2 symlinks are supported, but might require
  `$ fsutil behavior set SymlinkEvaluation L2L:1 R2R:1 L2R:1 R2L:1 #`.
  This includes symlinks to UNC paths, e.g., as Administrator
  `$ cmd /c 'mklink /d c:\home\rmainz \\derfwpc5131_ipv6@NFS@2049\export\home2\rmainz' #`
  and then `$ cd /cygdrive/c/home/rmainz/ #` should work

- performance: All binaries are built without any optimisation, so the
  filesystem is much slower than it could be.

- bad performance due to Windows Defender AntiVirus:

  - Option 1: disable Windows defender realtime monitoring (requires
    Administrator shell)

        powershell -Command 'Set-MpPreference -DisableRealtimeMonitoring 1'

  - Option 2: Add "`nfsd.exe`", "`nfsd_debug.exe`", "`ksh93.exe`",
    "`bash.exe`", "`git.exe`" and other offending commands to the
    process name whitelist.

- performance: Use `vmxnet3` in VMware to improve performance

- ACLs are supported via the normal Windows ACL tools, but on Linux
  require the `nfs4_getfacl`/`nfs4_setfacl` utilities to see the data.

  **Example 1** (assuming that Windows, Linux NFSv4 client and NFSv4
  server have a user "siegfried_wulsch"):

  - On Windows on a NFSv4 filesystem:

        $ icacls myhorribledata.txt /grant "siegfried_wulsch:WD" #

  - On Linux NFSv4 clients you will then see this:

        $ nfs4_getfacl myhorribledata.txt
        A::OWNER@:rwatTcCy
        A::siegfried_wulsch@global.loc:rwatcy
        A::GROUP@:rtcy
        A::EVERYONE@:rtcy

  **Example 2** (assuming that Windows, Linux NFSv4 client and NFSv4
  server have a group "cygwingrp2"):

  - On Windows on a NFSv4 filesystem:

        $ icacls myhorribledata.txt /grant "cygwingrp2:(WDAC)" /t /c #

  - On Linux NFSv4 clients you will then see this:

        $ nfs4_getfacl myhorribledata.txt
        A::OWNER@:rwatTcCy
        A::GROUP@:rtcy
        A:g:cygwingrp2@global.loc:rtcy
        A::EVERYONE@:rtcy

- `nfs_mount.exe` vs. reserved ports: By default the NFSv4 server on
  Solaris, Illumos, Linux etc. only accepts connections if the NFSv4
  client uses a "privileged (TCP) port", i.e., using a TCP port number
  \< 1024. If `nfsd.exe`/`nfsd_debug.exe` is started without the Windows
  privilege to use reserved ports, then a mount attempt can fail. This
  can be worked around on the NFSv4 server side - on Linux using the
  "insecure" export option in `/etc/exports` and on Solaris/Illumos
  using export option "resvport" (see `nfs(5)`).

- Accessing mounts from a VMware/QEMU/VirtualBox VM using NAT requires
  the the "insecure" export option in `/etc/exports` and on
  Solaris/Illumos using export option "resvport" (see `nfs(5)`), as the
  NFSv4 client source TCP port will be \>= 1024.

- Install: Adding Windows accounts+groups to the NFSv4 server:
  `ms-nfs41-client` comes with `/sbin/cygwinaccount2nfs4account` to
  convert the Win32/Cygwin account information of the (current)
  user+groups to a small script for the NFSv4 server to set-up these
  accounts on the server side.

- `nfs_mount -o sec=none ... #` works with Solaris 11.4 nfsd, but might
  require Linux kernel commit
  <https://git.kernel.org/pub/scm/linux/kernel/git/cel/linux.git/patch/?id=bb4f07f2409c26c01e97e6f9b432545f353e3b66>
  ("nfsd: Fix NFSD_MAY_BYPASS_GSS and NFSD_MAY_BYPASS_GSS_ON_ROOT") to
  work.

# Known issues

- The kernel driver ("`nfs41_driver.sys`") does not yet have a
  cryptographic signature for SecureBoot - which means it will only work
  if SecureBoot is turned off (otherwise
  `$ /sbin/msnfs41client install #` will FAIL!)

- If `nfsd_debug.exe` crashes or gets killed, the only safe way to run
  it again requires a reboot

- LDAP support does not work yet

- Attribute caching is too aggressive

- Caching in the kernel does not always work. For example
  `$ tail -f ... #` does not not see new data. Workaround: Use GNU
  tail'S `$ tail --follow=name ... #` Working theory is that this is
  related to FCB caching, see `|FCB_STATE_FILESIZECACHEING_ENABLED|`, as
  the `nfs41_driver.sys` kernel module does not see the `|stat()|`
  syscalls. But `$ tail -f ... #` always works for a moment if something
  else opens the same file.

- Unmounting and then mounting the same filesystem causes issues as the
  name cache in `nfsd*.exe` is not flushed on unmount, including
  leftover delegations.

- `krb5p` security with AES keys do not work against the linux server,
  as it does not support gss krb5 v2 tokens with rotated data.

- When recovering opens and locks outside of the server's grace period,
  client does not check whether the file has been modified by another
  client.

- If `nfsd.exe` is restarted while a drive is mapped, that drive needs
  to be remounted before further use.

- Does not allow renaming a file on top of an existing open file.
  Connectathon's special test `op_ren` has been commented out.

- File access timestamps might be wrong for delegations.

- Extended attributes are supported with some limitations:

  - a\) the server must support NFS Named Attributes (e.g. Solaris,
    Illumos, FreeBSD 15, but NOT Linux nfsd),

  - b\) the order of listings cannot be guaranteed by NFS, and

  - c\) the EaSize field cannot be reported for directory queries of
    `FileBothDirInformation`, `FileFullDirInfo`, or `FileIdFullDirInfo`.

- Win10/32bit-only: `$ net use H: /delete #` does not work, use
  `$ nfs_umount 'H'` instead \#

- Windows event log can list errors like "MUP 0xc0000222"
  (`|STATUS_LOST_WRITEBEHIND_DATA|`) in case the disk on the NFSv4
  server is full and outstanding writes from a memory-mapped file fail.
  Example:

      {Fehler beim verzoegerten Schreibvorgang} Nicht alle Daten fuer die
      Datei "\\34.159.25.153@NFS@2049\exportexport\gcc\lto-dump.exe"
      konnten gespeichert werden. Daten gingen verloren.
      Dieser Fehler wurde von dem Server zurueckgegeben, auf dem sich die
      Datei befindet. Versuchen Sie, die Datei woanders zu speichern.

- [VHD/VHDX
  disks](https://learn.microsoft.com/en-us/windows-server/storage/disk-management/manage-virtual-hard-disks)
  currently (Win10, Win11) cannot use files on ms-nfs41-client/NFSv4
  filesystems as storage. It seems the Windows code makes explicit
  checks for SMB filesystems, and rejects any non-SMB filesystems.

  As an alternative `filedisk-sparse`
  (<https://github.com/gisburn/filedisk-sparse/>) can be used to mount
  (sparse) files as disks or CDROM images.

  This can also be used to host per-machine software installations/data
  storage (e.g. use
  `filedisk /mount 35 'N:\winntfs_filedisk_003.img' S:` as global mount
  which require NTFS or ReFS, but should be physically hosted on the NFS
  server.

- Creating a new Win32 file/dir with an ACL only works with NFS servers
  which support `FATTR4_ACL`/`FATTR4_DACL` for `OPEN`/`CREATE`
  operations.

  So far FreeBSD 14.3 and the NFS-Ganesha NFS servers are known to
  support this, while Linux 6.12.\*, Solaris 11.4 and Illumos NFS
  servers ignore the ACL on `OPEN`/`CREATE` operations.

# Troubleshooting && finding bugs/debugging

- `nfsd_debug.exe` has the `-d` option to set a level for debug output.
  Edit `/sbin/msnfs41client` to set the `"-d"` option.

- The "msnfs41client" script has the option "`watch_kernel_debuglog`" to
  get the debug output of the kernel module.

  Run as Administrator: `$ /sbin/msnfs41client watch_kernel_debuglog #`

  Currently requires DebugView
  (<https://learn.microsoft.com/en-gb/sysinternals/downloads/debugview>)
  to be installed.

- Watching network traffic:

  - Use `$ /sbin/msnfs41client watch_nfs_traffic #` to watch the NFS
    network traffic

  - WireShark has a command line tool called "`tshark`", which can be
    used to see NFSv4 traffic. As NFSv4 uses RPC you have to filter for
    RPC, and the RPC filter automatically identifies NFSv4 traffic on
    its RPC id. Example for Windows: (for NFSv4 default TCP port "2049",
    replace "2049" with the desired port if you use a custom port; use
    "ipconfig" to find the correct interface name, in this case
    "Ethernet0"):

        $ nfsv4port=2049 ; /cygdrive/c/Program\ Files/Wireshark/tshark \
          -f "port $nfsv4port" -d "tcp.port==${nfsv4port},rpc" -i Ethernet0

  - If you are running inside a VMware VM on a Linux host it might
    require `$ chmod a+rw /dev/vmnet0 #` on VMware host, so that the VM
    can use "Promiscuous Mode".

# Development

## Source code

Source code can be obtained from
<https://github.com/kofemann/ms-nfs41-client> or as git bundle from
`/usr/src/msnfs41client/msnfs41client_git.bundle`

## Building ms-nfs41-client

### Building ms-nfs41-client using Cygwin+Makefile

#### Required Software

- **Option 1:** Windows 10 with Visual Studio 2019 Community

  - Start Visual Studio 2019 installer and import the installer config
    file `ms-nfs41-client/build.vc19/ms-nfs41-client_vs2019.vsconfig`,
    and then install Visual Studio.

    > [!NOTE]
    > Due to a bug in the VS installer, it is sometimes required to
    > manually add another (random) component to be installed;
    > otherwise, the imported config might be ignored.

  - WDK for Windows 10, version 2004, from
    <https://go.microsoft.com/fwlink/?linkid=2128854>

  - Cygwin 64bit \>= 3.5.0

  - PanDoc document converter, from
    <https://github.com/jgm/pandoc/releases/download/3.7.0.1/pandoc-3.7.0.1-windows-x86_64.msi>

- **Option 2:** Windows 11 with Visual Studio 2022 Community

  - Start Visual Studio 2022 installer and import the installer config
    file `ms-nfs41-client/build.vc19/ms-nfs41-client_vs2022.vsconfig`,
    and then install Visual Studio.

    > [!NOTE]
    > Due to a bug in the VS installer, it is sometimes required to
    > manually add another (random) component to be installed;
    > otherwise, the imported config might be ignored.

  - WDK for Windows 11, version 1591, from
    <https://go.microsoft.com/fwlink/?linkid=2286137>

  - Cygwin 64bit \>= 3.5.0

  - PanDoc document converter, from
    <https://github.com/jgm/pandoc/releases/download/3.7.0.1/pandoc-3.7.0.1-windows-x86_64.msi>

- **Option 3 (EXPERIMENTAL):** Windows 10 with Visual Studio 2026
  Community Insiders

  - Start Visual Studio 2026 installer and import the installer config
    file `ms-nfs41-client/build.vc19/ms-nfs41-client_vs2026.vsconfig`,
    and then install Visual Studio 2026 Community Insiders.

  - WDK for Windows 10, version 2004, from
    <https://go.microsoft.com/fwlink/?linkid=2128854>, and then copy the
    `Microsoft.DriverKit.Build.Tasks.16.0.dll` to
    `Microsoft.DriverKit.Build.Tasks.18.0.dll`:

        cp '/cygdrive/c/Program Files (x86)/Windows Kits/10/build/bin/Microsoft.DriverKit.Build.Tasks.16.0.dll' '/cygdrive/c/Program Files (x86)/Windows Kits/10/build/bin/Microsoft.DriverKit.Build.Tasks.18.0.dll'

  - Cygwin 64bit \>= 3.5.0

  - PanDoc document converter, from
    <https://github.com/jgm/pandoc/releases/download/3.7.0.1/pandoc-3.7.0.1-windows-x86_64.msi>

#### Build the Project

- **Windows 10: Using Visual Studio 2019+Cygwin command line
  (bash/ksh93):**

      # this creates a 32bit+kernel+64bit-kernel build for Windows 10+11
      export PATH="/cygdrive/c/Program Files (x86)/Microsoft Visual Studio/2019/Community/MSBuild/Current/Bin/:$PATH"
      git clone https://github.com/kofemann/ms-nfs41-client.git
      cd ms-nfs41-client
      # "retarget" VS platform toolset to "v142"
      # ("v142" should remain the default when comitting)
      sed -i -E 's/<PlatformToolset>v...<\/PlatformToolset>/<PlatformToolset>v142<\/PlatformToolset>/g' $(find 'build.vc19' -name \*.vcxproj)
      cd cygwin
      # get default WDK Test Certificate SHA1 ThumbPrint value for code signing
      export CERTIFICATE_THUMBPRINT="$(powershell -c 'Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object {$_.Subject -like "*WDKTestCert*"} | Select-Object -ExpandProperty Thumbprint')"
      make build
      make installdest
      make bintarball

- **Windows 11: Using Visual Studio 2022+Cygwin command line
  (bash/ksh93):**

      # this creates a 64bit-kernel only build for Windows 11
      export PATH="/cygdrive/c/Program Files/Microsoft Visual Studio/2022/Community/MSBuild/Current/Bin/:$PATH"
      git clone https://github.com/kofemann/ms-nfs41-client.git
      cd ms-nfs41-client
      # "retarget" VS platform toolset to "v143"
      # ("v142" should remain the default when comitting)
      sed -i -E 's/<PlatformToolset>v...<\/PlatformToolset>/<PlatformToolset>v143<\/PlatformToolset>/g' $(find 'build.vc19' -name \*.vcxproj)
      cd cygwin
      # get default WDK Test Certificate SHA1 ThumbPrint value for code signing
      export CERTIFICATE_THUMBPRINT="$(powershell -c 'Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object {$_.Subject -like "*WDKTestCert*"} | Select-Object -ExpandProperty Thumbprint')"
      make build64
      make installdest64
      make bintarball64

- **Windows 10: Using Visual Studio 2026 Community Insiders+Cygwin
  command line (bash/ksh93):**

      # this creates a 32bit+kernel+64bit-kernel build for Windows 10+11
      export PATH="/cygdrive/c/Program Files/Microsoft Visual Studio/18/Insiders/MSBuild/Current/Bin/:$PATH"
      git clone https://github.com/kofemann/ms-nfs41-client.git
      cd ms-nfs41-client
      # "retarget" VS platform toolset to "v145"
      # ("v142" should remain the default when comitting)
      sed -i -E 's/<PlatformToolset>v...<\/PlatformToolset>/<PlatformToolset>v145<\/PlatformToolset>/g' $(find 'build.vc19' -name \*.vcxproj)
      cd cygwin
      # get default WDK Test Certificate SHA1 ThumbPrint value for code signing
      export CERTIFICATE_THUMBPRINT="$(powershell -c 'Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object {$_.Subject -like "*WDKTestCert*"} | Select-Object -ExpandProperty Thumbprint')"
      make build
      make installdest
      make bintarball

> [!NOTE]
> `make installdest` or `make installdest64` can fail on SMB/NFSv4.1
> filesystems with a "link.exe" crash. The workaround is to disable
> incremental linking before building, e.g., do:
>
>     cd ms-nfs41-client
>     sed -i -E 's/<LinkIncremental>true<\/LinkIncremental>/<LinkIncremental>false<\/LinkIncremental>/g' $(find build.vc19 -name \*.vcxproj)
>
> This Visual Studio bug is tracked as
> <https://developercommunity.visualstudio.com/t/Visual-Studio-link.exe-crashes-on-networ/10735424>
> ("Visual Studio link.exe crashes on network filesystem").

### Testing

See `tests/manual_testing.txt`

# Mailing list

Please direct any questions to
<ms-nfs41-client-devel@lists.sourceforge.net> (list
[archive](https://sourceforge.net/p/ms-nfs41-client/mailman/ms-nfs41-client-devel/))

\#EOF.
