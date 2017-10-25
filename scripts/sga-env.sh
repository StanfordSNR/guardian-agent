#!/bin/sh 

# Sets environment variables and aliases to enable ssh guardian gent
# for commonly used tools

# Set environment variables overriding the ssh program
export RSYNC_RSH=sga-ssh
export GIT_SSH_COMMAND=sga-ssh

# For tools not providing environment variables, set aliases
alias mosh="mosh --ssh=sga-ssh"
alias scp="scp -S sga-ssh"
