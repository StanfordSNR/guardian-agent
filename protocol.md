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

## Protocol Timeline
Through its use, the protocol (our agent layer) relies on three levels of abstraction:
```c
    Protocol    --- APPLY POLICY/HANDOFF --- AGENT LAYER
                ---     FW MSG           --- SSH LAYER
                ---     FW PKT           --- TCP LAYER
```

The protocol works in three main stages:
1.Establishing a connection A-S
1.Delegating a restricted connection C-A-S
1.Handing off the restricted connection C-S

At all times, state changes are initiated by the Client.

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

## Restricted SSH Connection
Once a successfull SSH connection has been established between the agent
and the server, the agent provides the client with a **restricted SSH
Connection** to the server, by providing restricted forwarding of
messages from the SSH Protocol. The client can request the
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

### Blocked Request
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

## Connection Handoff
Once the client has received the ```SSH_AGENT_SUCCESS``` message, it can
initiate a connection handoff. To do this, we leverage the fact that SSH
allows a client to initiate a "Key Re-Exchange" at any time: in this case,
our client asks the server to initiate a KRE, using the agent's existing
connection with the server.

We choose to do this using a KRE as it simplifies the state the agent must
hand off to the client.
Simply said, we are choosing to have the client negotiate the new connection
with the server, rather than have the agent transfer its existing cryptographic
state to the client, as this approach might be problematic if client and agent
do not support the same cipher suites, for instance. We can do this using our
Connection Service primitives defined above.

The KRE is performed by the client using the above mentioned ***Restricted SSH
Connection*** using SSH_MSG_KEXINIT to freeze the connection state.
Thereafter, the ***client*** MUST NOT send further ssh messages, but may
receive messages from the server, forwarded by the agent.
(See [SSH RFC Section 7.2](https://tools.ietf.org/html/rfc4253)).

Note: The Server can start transmitting messages under the new key (that it
shares with the client) as soon as it has sent its part of DH to the client.
The client cannot tell that it has the key until the agent returns the decrypted
DH message to it. There is a risk that the client will receive messages encrypted
under the new key before it has formed said key.
To deal with this issue, no change is required: the logic is as follows:
1.Until the client has the new key, it should forward all messages to the Agent
1.The agent should stop trying to decrypt messages once it has received the NEW
KEYS message (it will have sent DH back to the client by then), and just forward
them back to the client.

There needs to be a mutual FIN between agent and client in order for them to
close the connection, and send the NEW_KEYS message (encrypted under the old key)
from the agent to the server.

Note 2: avoid all this by doing full state transfer and not KRE?

To complete the KRE, the ***client*** can request the connection parameters
from the ***agent*** by sending the following message:
```c
    byte                    SSH_AGENTC_EXTENSION
    string                  "delegated-connection-params-request@cs.stanford.edu"
```

It is up to the agent to determine whether this operation is allowed.
On success, it will return the connection parameters:
```c
    byte                    SSH_AGENT_SUCCESS
    string                  "delegated-connection-params-respo
    string                  sequence number
    string                  session id
```

