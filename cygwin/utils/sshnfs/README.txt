#
# sshnfs/README.txt
#

**** ToDo:
- ksh93 getopt argument parsing
- Correct POSIX exit codes
- c.destination_nfs_port should be a command line option
- How can a non-standard (TCP/2049) NFS port be specified for
  ssh+nfs:// URLs be specified ?
- Debug messages should go to stderr
- Linux: Add mount.nfs -o nconnect=4 (see
  https://www.suse.com/support/kb/doc/?id=000019933)


**** Testing:
- Check whether SSH -p port works
- Check whether user in ssh+nfs:// URLs works
- Check whether ports in ssh+nfs:// URLs works

# EOF.
