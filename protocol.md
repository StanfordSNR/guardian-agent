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

## Starting a new delegated connection
The client requests the agent to setup a new SSH connection with the server by
first establishing a new TCP connection with the server, hereby referred to as
the **server socket**, and then sending to the agent the following  message:
```c
	byte                    SSH_AGENTC_EXTENSION
    string                  "delegated-connect@cs.stanford.edu"
```

The agent then replies as following:
1. If this extension is not supported by the agent, the agent replies with an
   empty ```SSH_AGENT_FAILURE``` message.
1. If the request is denied, the agent replies with a
   ```SSH_AGENT_EXTENSION_FAILURE``` message.
1. If the request is approved, the agent replies with a
   ```SSH_AGENT_EXTENSION_CONTINUE``` empty message.

If the request is approved, the TCP connection to the server is forwarded to
the agent by the client as follows. Upon receiving a packet from the server
(on the server socket), the client sends the following message to the agent:
```c
	byte                    SSH_AGENTC_EXTENSION
    string                  "delegated-packet-from-server@cs.stanford.edu"
	byte[]                  original_packet
```
To send a packet to the server, the agent sends to the client the following
message:
```c
	byte                    SSH_AGENT_EXTENSION
    string                  "delegated-packet-to-server@cs.stanford.edu"
	byte[]                  original_packet
```

The agent then tries to establish a new SSH connection to the server over
the forwarded TCP connection. The agent then sends to the client one of the
following messages:
1. If the agent fails to establish the SSH connection (for example if it
   fails to authenticate the server, or fails to authenticate itself to the
   server etc.), it sends a ```SSH_AGENT_EXTENSION_FAILURE``` message.
   Upon receiving this message, the client stops to forward packets between
   the server and the agent.
1. Otherwise, if the agent successfully connects to the server, it sends
   an ```SSH_AGENT_SUCCESS``` empty message. The client proceeds with
   forwarding packets between the server and the agent by processing the two
   types of messages above.

## Restricted SSH Connection Service
Once a successfull SSH connection has been established between the agent
and the server, the agent provides the client with a **restricted SSH
Connection Service** to the server, by providing restrictged forwarding of
messages from the [SSH Connection
Protocol](https://tools.ietf.org/html/rfc4254). The client can request the
agent to forward a SSH Connection Protocol Message to the server by
encapsulating it in the following message, which is sent to the agent:
```c
	byte                    SSH_AGENTC_EXTENSION
    string                  "delegated-message-to-server@cs.stanford.edu"
    string                  message
```
It is up to the agent to determine whether to allow the given message to be
forwarded to the server over the SSH connection. The agent sends messages
from the server to the client by encapsulating them in the following message:
```c
	byte                    SSH_AGENT_EXTENSION
    string                  "delegated-message-from-server@cs.stanford.edu"
    string                  message
```

###Blocked Requests
For simplicity, when the agent decides to block a message from being sent
to the server (for example to prevent execution of a specific command),
the agent returns the corresponding SSH Connection Protocol error message. For
example:
1. If the agent blocks a request to open channel (```SSH_MSG_CHANNEL_OPEN```),
it sends the client a ```"delegated-message-from-server@cs.stanford.edu"```
message containing an encapsulated ```SSH_MSG_CHANNEL_OPEN_FAILURE``` message.
1. If the agent blocks a request to execute a command within a channel
(```SSH_MSG_CHANNEL_REQUEST```), it sends the client a
```"delegated-message-from-server@cs.stanford.edu"``` message
containing an encapsulated ```SSH_MSG_CHANNEL_FAILURE``` message.
