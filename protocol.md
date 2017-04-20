# Restricted SSH Delegation and Handoff

## Overview
This is a protocol extension to the [SSH Agent
Protocol](https://tools.ietf.org/id/draft-miller-ssh-agent-00.html).
The goal of the extension is to allow an **SSH client**, running on a partially
trusted machine, to request the **SSH agent**, running on a trusted machine,
to execute commands on an **SSH server**, such that the identity of
the server as well as the SSH session command can be verified by the SSH agent.

![SSH Level](SSHLevel.png)

At some point the client can potentially request request tha connectionto be handed-off to
him.

![After Handoff](AfterHandoff.png)

## Message Format

Complying with the base protocol, all messages consist of length and contents.
```c
    uint32                   message_length
    byte[message_length]     message_contents
```
The first byte of the contents always indicates the type of the message.

The agent protocol includes an optional extension mechanism that allows
vendor-specific and experimental messages to be sent via the agent protocol.
Therefore, all extension messages from the ***client*** and the ***server***
consist of:
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

## Restricted delegated SSH Connection
### Starting a new delegated connection
The ***client*** requests the ***agent*** to setup a new SSH connection with
the ***server*** using the following  message:
```c
    byte                    SSH_AGENTC_EXTENSION
    string                  "delegated-connect@cs.stanford.edu"
```

The agent then tries to establish a new SSH connection to the server over
the [forwarded TCP connection](#tcp-forwarding). The agent then sends to the
client one of the following messages:
1. If this extension is not supported by the agent, the agent replies with an
   empty ```SSH_AGENT_FAILURE``` message.
1. If the agent fails to establish the SSH connection (for example if it
   fails to authenticate the server, or fails to authenticate itself to the
   server etc.), it sends a ```SSH_AGENT_EXTENSION_FAILURE``` message.
   Upon receiving this message, the client stops to forward packets between
   the server and the agent.
1. Otherwise, if the agent successfully connects to the server, it sends
   an ```SSH_AGENT_SUCCESS``` empty message. The client proceeds with
   forwarding packets between the server and the agent by processing the two
   types of messages above.


### SSH Message Forwarding
Once a successfull SSH connection has been established between the agent
and the server, the agent provides the client with a **restricted delegated SSH
connection** to the server, by providing restricted forwarding of
messages from the SSH Protocol. The client can request the agent to forward a
SSH message to the server by encapsulating it in the following message and sending it
to the agent:
```c
    byte                    SSH_AGENTC_EXTENSION
    string                  "delegated-message-to-server@cs.stanford.edu"
    byte[]                  message
```
It is up to the agent to determine whether to allow the given message to be
forwarded to the server over the SSH connection. The agent sends messages
from the server to the client by encapsulating them in the following message:
```c
    byte                    SSH_AGENT_EXTENSION
    string                  "delegated-message-from-server@cs.stanford.edu"
    byte[]                  message
```

### Blocked Messages
For simplicity, when the agent decides to block a message from being sent
to the server (for example to prevent execution of a specific command),
the agent returns the corresponding SSH error message. For
example:
1. If the agent blocks a request to open channel (```SSH_MSG_CHANNEL_OPEN```),
it sends the client a ```"delegated-message-from-server@cs.stanford.edu"```
message containing an encapsulated ```SSH_MSG_CHANNEL_OPEN_FAILURE``` message.
1. If the agent blocks a request to execute a command within a channel
(```SSH_MSG_CHANNEL_REQUEST```), it sends the client
a ```"delegated-message-from-server@cs.stanford.edu"``` message
containing an encapsulated ```SSH_MSG_CHANNEL_FAILURE``` message.



### Connection Handoff
Once the client has received the ```SSH_AGENT_SUCCESS``` message, it can
initiate a connection handoff. To do this, we leverage the fact that SSH
allows a client to initiate a
["Key Re-Exchange"](https://tools.ietf.org/html/rfc4253#section-9) at any time.
In this case, our client initiates a KRE over the agent's existing connection
with the server, by using the
[restricted SSH forwarding methods](#ssh-message-forwarding).

We choose to do this using a KRE as it simplifies the state the agent must
hand off to the client.
Simply said, we are choosing to have the client negotiate the new connection
with the server, rather than have the agent transfer its existing cryptographic
state to the client, as this approach might be problematic if client and agent
do not support the same cipher suites, for instance.

The KRE is initiated by the client sending a ```SSH_MSG_KEXINIT``` message.
Note that in accordance with the SSH protocol, the client is
[restricted](https://tools.ietf.org/html/rfc4253#page-19) to the
types of messages it is allowed to send during key exchange (and effectively
the connection is 'frozen'). However, additional messages might be received
from the server, before it responds with its ```SSH_MSG_KEXINIT``` message.

The KRE is completed for each direction separately, when the sending party
sends a ```SSH_MSG_NEWKEYS``` message.
Once the agent forwards both ```SSH_MSG_NEWKEYS``` messages (one at each
direction), it completes the handoff by sending the following message to the
client:
```c
    byte                    SSH_AGENT_EXTENSION
    string                  "handoff-connection@cs.stanford.edu"
    uint32                  outgoing_seq_num
    uint32                  incoming_seq_num
    uint32                  incoming_tcp_seq_num
```
where ```outgoing_seq_num``` and ```incoming_seq_num``` are the next SSH
sequence numbers, and ```incoming_seq_num``` is the sequence number of the
first byte on the inbound TCP connection that needs to be processed by the
client (i.e., the position in the TCP stream of the first SSH message encrypted
with the new keys). This is required since the Server can start transmitting packets
encrypted using the new key as soon as it has sent its ```SSH_MSG_NEWKEYS```
message, and there is a risk that the client will receive messages encrypted
under the new key before it has formed said key.

There needs to be a mutual FIN between agent and client in order for them to
close the connection, and send the ```SSH_MSG_NEWKEYS``` message (encrypted under
the old key) from the agent to the server.


## TCP Forwarding
To make the handoff of the SSH connection transparent to the server, the
SSH connection must remain on the same TCP connection both before and after the
handoff. Since one of the motivations for the protocol is to allow the command data
to be sent directly from the client to the server (rather than
proxied through a potentillay slower link throght the agent), the TCP connection
must be directly from the client to the server.
Also note, that the server can be even unreachable from the agent
on the network level (for example if the server is on some internal network,
and the client is a DMZ host on the same network).
The TCP connection to the server is thus forwarded to the agent by the client
as follows.

![Before Handoff](Connectivity.png)

Upon receiving a packet from the server, the client sends the
following message to the agent:
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

Messages are not acked.
