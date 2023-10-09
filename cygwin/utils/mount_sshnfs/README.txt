#
# mount_sshnfs/README.txt
#

**** ToDo:
- Add umount -f option
- Add umount -v option
- Add mount -v/-vv/-vvv option
- Fix FIXME stuff
- on mount: Check whether the mount point exists
- mounting should enforce that we only try NFSv4, and not try NFSv3
- Implement "status" command to check on mount point and ssh
  forwarding process
- Implement "restart_forwarding" command to restart the ssh
  forwarding process if it terminated for some reason
- Debug messages should go to stderr
- Linux: Add mount.nfs -o nconnect=4 (see
  https://www.suse.com/support/kb/doc/?id=000019933)
- Add Linux umount helper support, see umount(8) HELPER section

# EOF.
