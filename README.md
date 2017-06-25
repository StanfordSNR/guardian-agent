# SSH Guardian Agent

SSH Guardian Agent is an SSH client providing secure SSH agent forwarding.

* [Installation](#installation)
* [Building](#building)
* [Basic Usage](#basic-usage)
* [Advanced Usage](#advanced-usage)
   * [Forwarding only](#forwarding-only)
   * [Prompt types](#prompt-types)
   * [Customizing the SSH command](#customizing-the-ssh-command)
   * [Stub location](#stub-location)
* [Troubleshooting](#troubleshooting)
* [Development](#development)

## Installation
Using SSH Guardian Agent requires installation both on your local machine (the one with your SSH private keys) and on each of the remote machines you want to securely forward SSH agent to (the machines on which you want to run an SSH client without having the keys on them). No installation is required on the server side.

1. Install the following dependencies:
  * OpenSSH client
  * ssh-askpass (MacOS users can use the [following port](https://github.com/theseal/ssh-askpass))
2. Obtain the [latest tarball](https://github.com/dimakogan/ssh/releases/latest) for your platform. 
Alternatively, you may opt to [build from source](#building).
3. Extract the two binaries (`sshguard` and `sshfwdstub`) from the tarball to a directory in the user's PATH.

## Building
1. [Install go](https://golang.org/doc/install)
2. Get the sources and needed dependencies
```
go get github.com/dimakogan/ssh

go get github.com/hashicorp/yamux
go get github.com/kballard/go-shellquote
go get github.com/sternhenri/interact
```
3. Build
```
go build github.com/dimakogan/ssh/gossh/sshguard
go build github.com/dimakogan/ssh/gossh/sshfwdstub
```
## Basic Usage

Make sure the client is installed on your local machine and both the client and the stub
are installed on the remote machine.

Start an SSH session on a remote machine with secure agent forwarding enabled:

```
[local]$ sshguard -A <remote>
```  


To use SSH remotely with the forwarded agent:
```
[remote]$ sshguard -d <server> [command]
```

This should trigger a local graphical consent prompt explicitly identifying `remote`, `server` and `command`.

## Advanced Usage

### Forwarding only
To enable secure agent forwarding to a remote machine without starting an interactive session on the remote host:

```
[local]$ sshguard -N -A <remote>
```

### Prompt types

Guardian agent supports two types of interactive prompts: graphical and terminal-based.
The graphical prompt requires the `DISPLAY` environment to be set to the appropriate X11 server.  
If running in a terminal-only session, a textual prompt may be used instead. However, the same terminal cannot be used both for textual prompts and for executing remote commands (or interactive sessions).
Therefore, terminal-based prompt may only be used when [forwarding only](#forwarding-only) (i.e., the `-N` flag is specified).

### Customizing the SSH command

When setting up secure agent forwarding, the default SSH client on the local machine is used for setting up the connection. This requires `ssh` to be found in the user's `PATH`. To specify an alternative SSH client or specifying additional argument to the client, the `--ssh` and `--ssh_args` command-line flags may be used. 

Specifying additional ssh arguments is currently not supported on the remote host (i.e., when using the `-d` flag).  

### Stub location

If the `sshfwdstub` is not installed in the user's `PATH` on the remote machine, its location must be specified when setting up secure agent forwarding from the local machine:

```
[local]$ sshguard -A --stub=<PATH-TO-STUB> <remote>
```

## Troubleshooting

In case of [unexpected behavior](https://en.wikipedia.org/wiki/Bug_(software)), please consider opening an issue in our [issue tracker](https://github.com/dimakogan/ssh/issues).
We'd also greatly appreciate if you could run the tool in debug mode by setting the `--debug` and `--logfile=<LOG-FILE>` flags and attach the log file to the issue.

## Development
[Protocol specification](doc/protocol.md)
