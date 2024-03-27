#
# /etc/ksh.kshrc+~/.kshrc are sourced only for interactive shells
#

# default prompt
PS1=$'\E[1;32m$(/usr/bin/logname)@$(/usr/bin/hostname) \E[1;33m${PWD/~(Sl-r)$HOME/"~"}\E[0m\n$ '
# default editor mode
set -o gmacs
