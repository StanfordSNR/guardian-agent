# SSH Guardian Agent

SSH Guardian Agent is an SSH client providing secure SSH agent forwarding.


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

# Development
[Protocol specification](doc/protocol.md)
