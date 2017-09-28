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
2. Obtain the [latest release](https://github.com/StanfordSNR/guardian-agent/releases/latest) for your platform. 
Alternatively, you may opt to [build from source](#building).
3. Extract the two binaries (`ssh-guard-agent` and `ssh-fwd-stub`) from the
   tarball to a directory in the user's PATH.

## Building from Source
1. [Install go](https://golang.org/doc/install)
2. Get and build the sources:
```
go get github.com/StanfordSNR/guardian-agent/cmd/ssh-guard-agent
go get github.com/StanfordSNR/guardian-agent/cmd/ssh-fwd-stub
```
3. The binaries (`ssh-guard-agent` and `ssh-fwd-stub`) should be found in `$GOPATH/bin`.

## Basic Usage

Make sure the client is installed on your local machine and both the client and the stub
are installed on the remote machine.

Start an SSH session on a remote machine with secure agent forwarding enabled:

```
[local]$ ssh-guard-agent -A <remote>
```  


To use SSH remotely with the forwarded agent:
```
[remote]$ ssh-guard-agent -d <server> [command]
```

This should trigger a local graphical consent prompt explicitly identifying `remote`, `server` and `command`.

### Stub location

If the `ssh-fwd-stub` is not installed in the user's `PATH` on the remote machine, its location must be specified when setting up secure agent forwarding from the local machine:

```
[local]$ ssh-guard-agent -A --stub=<PATH-TO-STUB> <remote>
```

## Advanced Usage

### Forwarding only
To enable secure agent forwarding to a remote machine without starting an interactive session on the remote host:

```
[local]$ ssh-guard-agent -N -A <remote>
```

### Prompt types

Guardian agent supports two types of interactive prompts: graphical and terminal-based.
The graphical prompt requires the `DISPLAY` environment to be set to the appropriate X11 server.  
If running in a terminal-only session, a textual prompt may be used instead. However, the same terminal cannot be used both for textual prompts and for executing remote commands (or interactive sessions).
Therefore, terminal-based prompt may only be used when [forwarding only](#forwarding-only) (i.e., the `-N` flag is specified).

### Customizing the SSH command

When setting up secure agent forwarding, the default SSH client on the local machine is used for setting up the connection. This requires `ssh` to be found in the user's `PATH`. To specify an alternative SSH client or specifying additional argument to the client, the `--ssh` and `--ssh_args` command-line flags may be used. 

Specifying additional ssh arguments is currently not supported on the remote host (i.e., when using the `-d` flag).  

## Troubleshooting

In case of [unexpected behavior](https://en.wikipedia.org/wiki/Bug_(software)), please consider opening an issue in our [issue tracker](https://github.com/StanfordSNR/guardian-agent/issues).
We'd also greatly appreciate if you could run the tool in debug mode by setting the `--debug` and `--logfile=<LOG-FILE>` flags and attach the log file to the issue.

### Common issues

* Make sure the remote machine (or localhost if you are testing locally) has a running ssh daemon
* Make sure your keys to the remote are added to your ssh-agent so you can connect

## Development
[Detailed Design](doc/design.md)
