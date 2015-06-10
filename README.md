
# Windows NFS 4.1 Client Instructions

1.  [Building from Source](#build)
2.  [Installing Binaries](#install)
3.  [Disable the DFS Client](#dfs)
4.  [Ldap Configuration](#ldap)
5.  [Starting the Client](#startup)
6.  [Mounting](#mount)
7.  [Connectation](#cthon)
8.  [Known Issues](#issues)


## 1\. <a name="build">Building from Source</a>

### Requirements

*   Windows Vista, Windows Server 2008 R2, or Windows 7 (Windows XP and previous versions are not supported)
*   Microsoft Visual Studio 2010
*   Windows Driver Development Kit (WinDDK 6000 or later)
*   ms-nfs41-client source code:   
    `> https://github.com/kofemann/ms-nfs41-client.git`

### Building the rpc library and nfs client daemon

*   WinDDK does not include the ldap library, so we build the rpc library and nfs client daemon with Visual Studio 2010.

1.  Open Windows Explorer and navigate to **ms-nfs41-client\build.vc10**.
2.  Make a copy of **env.props.example**, and rename it to **env.props**.
3.  Open **env.props** in a text editor, and verify that the value in `<WDKPATH>C:\WinDDK\7600.16385.0</WDKPATH>` points to your WinDDK installation.
4.  Open the solution file **ms-nfs41-client.sln** in Visual Studio 2010.
5.  Select the desired configuration and platform (accessible via Build->Configuration Manager).
6.  Right-click on the **daemon** project and select Build. The project and its dependencies should build without errors. The resulting binaries, **nfsd.exe** and **libtirpc.dll**, can be found under **ms-nfs41-client\build.vc10\x64\Debug\**.

### Building the driver and utilities

1.  From the Start menu, open the WinDDK 'Checked Build Environment' for the target platform.
2.  Change directory to **ms-nfs41-client** and type `build`. All projects should build without errors.

### Signing the driver

1.  Open a WinDDK 'Checked Build Environment' as Administrator in this directory (right click and 'Run as administrator').
2.  Create a certificate for test-signing the driver ([Creating Test Certificates](http://msdn.microsoft.com/en-us/library/ff540213%28VS.85%29.aspx "msdn.microsoft.com")):   
    `> makecert /pe /ss PrivateCertStore /n CN=nfs41_driver nfs41_driver.cer`
3.  Use the certificate to sign **nfs41_driver.sys** ([Test-Signing a Driver File](http://msdn.microsoft.com/en-us/library/ff553467%28VS.85%29.aspx "msdn.microsoft.com")):   
    `> signtool sign /v /s PrivateCertStore /n nfs41_driver /t http://timestamp.verisign.com/scripts/timestamp.dll path\to\nfs41_driver.sys`

## 2\. <a name="install">Installing Binaries</a>

### Requirements

*   ms-nfs41-client binaries: **nfs41_driver.sys**, **nfs41_np.dll**, **libtirpc.dll**, **nfs_install.exe**, **nfsd.exe**, **nfs_mount.exe**
*   ms-nfs41-client configuration files: **nfs41_driver.cer**, **nfs41rdr.inf**, **install.bat**, **uninstall.bat**, **etc_netconfig**, **ms-nfs41-idmap.conf**
*   Microsoft Visual Studio 2010, or Microsoft Visual C++ 2010 Redistributable Libraries ([x86](https://www.microsoft.com/download/en/details.aspx?id=8328) or [x64](https://www.microsoft.com/download/en/details.aspx?id=13523)). An installer for the redistributable libraries are included with binary releases.

### Instructions

1.  Copy or extract all ms-nfs41-client binaries and configuration files into a directory that's convenient for testing.
2.  Run **vcredist_x*.exe** to install the Visual C++ Redistributable Libraries.
3.  Double-click on **nfs41_driver.cer** and select 'Install Certificate', then place it in the 'Trusted Root Certificate Authorities' store.
4.  Open a command prompt as Administrator in this directory.
5.  Install the driver and update the registry:   
    `> install.bat`
6.  Copy configuration files:   
    `> mkdir C:\etc`   
    `> copy etc_netconfig C:\etc\netconfig`   
    `> copy ms-nfs41-idmap.conf C:\etc\`
7.  Allow windows to load test-signed drivers:   
    `> bcdedit /set testsigning on`
8.  Reboot.

## 3\. <a name="dfs">Disable the DFS Client</a>

*   The Windows DFS client interferes with some requests, indicated by long delays during operation. See [http://support.microsoft.com/kb/171386](http://support.microsoft.com/kb/171386) for more information.

### Instructions

1.  Open **regedit.exe** and navigate to `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Mup`.
2.  Add a DWORD value named `DisableDfs` with a value of 1.

## 4\. <a name="ldap">Ldap Configuration</a>

### Requirements:

*   **C:\etc\ms-nfs41-idmap.conf** from [Installation](#install) step 7.

### Instructions

1.  Open **C:\etc\ms-nfs41-idmap.conf** in a text editor.
2.  Uncomment the `ldap_hostname` and `ldap_base` lines, and configure as appropriate to match your ldap server configuration (we'll add suggestions later).

## 5\. <a name="startup">Starting the Client</a>

*   If you've installed the binary distribution, you'll find two versions of the nfs client daemon: **nfsd.exe** and **nfsd_debug.exe**. **nfsd.exe** is built to run as a service, and does not provide easy access to debug output. We strongly recommend trying **nfsd_debug.exe** first (using the Instructions below) to verify that you can start the daemon and mount/unmount an nfs share. You can then close **nfsd_debug.exe** and start running **nfsd.exe** as a service with:  
    `> nfsd.exe -install`.

### Instructions

1.  From a Windows command prompt, run **nfsd.exe** to start the nfs client daemon. Leave this running in the background until all mapped drives are unmounted.   
    Usage:   
    `> nfsd.exe -d <debug level> [--noldap]`
    *   `<debug level>` determines the log verbosity (1, 2, 3 or 0 to disable)
    *   `--noldap` disables id mapping and uses a default uid=666 and gid=777
    *   `--uid, --gid` changes the default uid/gid when no mapping is available (must be nonzero)

## 6\. <a name="mount">Mounting</a>

### Instructions

1.  From a Windows command prompt run **nfs_mount.exe** to mount a share:   
    `> nfs_mount.exe Z: <server_name>:\`
2.  To specify the security flavor, add the 'sec=' mount option with sys, krb5, krb5i, or krb5p:   
    `> nfs_mount.exe -o sec=<flavor> Z: <server_name>:\`
3.  You can later unmount with:   
    `> nfs_mount.exe -d Z`

## 7\. <a name="cthon">Connectathon</a>

### Requirements

*   [Cygwin](http://www.cygwin.com "www.cygwin.com"), including packages gcc-core, make, time, tirpc, git
*   [Connectathon Test Suite](http://www.connectathon.org/nfstests.html "www.connectathon.org")
*   ms-nfs41-client source code (patches for connectathon are located in **ms-nfs41-client\tests**)

### Instructions

1.  Extract **nfstests.zip** into a directory that's convenient for testing (i.e. **cthon04**).
2.  Open a Cygwin shell, and change directory to **cthon04**.
3.  Create a git repository to track changes:   
    `> git init`   
    `> git add *`   
    `> git commit -m "files from nfstests.zip"`
4.  Apply all cthon patches:   
    `> git am /path/to/ms-nfs41-client/tests/*.patch`
5.  Build the tests:   
    `> make`
6.  Run the test suite on a mounted directory:   
    `> ./runtests -a -t z:/testdir`

## 8\. <a name="issues">Known Issues</a>

*   krb5p security with AES keys do not work against the linux server, as it does not support gss krb5 v2 tokens with rotated data.
*   When recovering opens and locks outside of the server's grace period, client does not check whether the file has been modified by another client.
*   If nfsd.exe is restarted while a drive is mapped, that drive needs to be remounted before further use.
*   Symbolic links are not supported in Cygwin. Connectathon's basic test8 and special test nfsidem have been commented out.
*   Does not allow renaming a file on top of an existing open file. Connectathon's special test op_ren has been commented out.
*   Extended attributes are supported with some limitations: a) the server must support [NFS Named Attributes](https://tools.ietf.org/html/rfc5661#section-5.3 "RFC 5661: 5.3\. Named Attributes"), b) the order of listings cannot be guaranteed by NFS, and c) the EaSize field cannot be reported for directory queries of FileBothDirInformation, FileFullDirInfo, or FileIdFullDirInfo.

Please direct any questions to [ms-nfs41-client-devel@lists.sourceforge.net](mailto:ms-nfs41-client-devel@lists.sourceforge.net).
