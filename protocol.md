# Session Delegation - SSH Agent Protocol Extension


## Overview
This is a protocol extension to the [SSH Agent Protocol
Draft](https://tools.ietf.org/id/draft-miller-ssh-agent-00.html).
The goal of the extension is to allow an **SSH client**, running on a partially
trusted machine, to request the **SSH agent**, running on a trusted machine,
to establish an SSH session with an **SSH server**, such that the identity of
the server as well as the SSH session command can be verified by the SSH agent.

The following diagram illustrates the parties in the protocol, as well as the
"network level" connectivity between them:
![Before Handoff](Connectivity.png)

## Message Format

Complying with the base protocol, all messages consist of length and contents.
```c
	uint32                   message_length
	byte[message_length]     message_contents
```
The first byte of the contents always indicates the type of the message.

The agent protocol includes an optional extension mechanism that allows
vendor-specific and experimental messages to be sent via the agent protocol.
Therefore, all extension messages from the client and the server consist of:
```c
    byte                    SSH_AGENTC_EXTENSION
    string                  extension_message_name
    byte[]                  extension_message_contents
```
and
```c
    byte                    SSH_AGENT_EXTENSION
    string                  extension_message_name
    byte[]                  extension_message_contents
```
respectively, where ```SSH_AGENTC_EXTENSION``` is defined by the base protocol,
and we define the ```SSH_AGENT_EXTENSION``` message number below.



## Requesting a new delegated session
The intermediary
