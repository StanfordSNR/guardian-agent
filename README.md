---



## <span style="color:red"> WARNING! </span>

<span style="color:red">

**This tool is in beta and we're working to improve it.
Feedback is greatly appreciated, but please use at your own risk.**

</span>

---

## SSH Guardian Agent

Traditional ssh-agent forwarding
[can](https://heipei.github.io/2015/02/26/SSH-Agent-Forwarding-considered-harmful/)
[be](https://news.ycombinator.com/item?id=9425805)
[dangerous](https://lyte.id.au/2012/03/19/ssh-agent-forwarding-is-a-bug/): the
local ssh-agent hast to sign opaque challenges using the user's private key,
without knowing (a) what intermediary host is asking for the signature, (b) what
remote server that intermediary host wants to authenticate to, or (c) what
command the intermediary host wants to execute on the remote server. 

A compromised intermediary can send rogue challenges and use the user's identity
to authenticate to other servers or to run unauthorized commands. So you might
enable ssh-agent forwarding and be asked yes or no on signing "something," and
you think it's allowing an EC2 machine to run "git push" to GitHub. But actually
it's allowing a different EC2 machine (that you also are logged in to) to
connect to some other sensitive server that you have permissions on and add an
evil key to your authorized_keys file.)

SSH Guardian Agent provides secure SSH agent forwarding. A user first runs
`sga-guard` on her local machine (on which she stores her private SSH keys) to
securely forward her SSH agent to an intermediary machine (e.g., on AWS). She
can then use `sga-ssh` on the intermediary machine as a drop-in replacement to
`ssh`. The local `sga-guard` verifies the identity of the **intermediary**, the
**remote server** and the **command**[<sup>*</sup>](#command-verification),
either by prompting the user or based on a stored security policy. After all the
details are verified, the connection is handed off to the intermediary (so the
bulk of the data is **not** proxied through the local host).

![Example](animation.gif)

* [Installation](#installation)
* [Basic Usage](#basic-usage)
* [Advanced Usage](#advanced-usage)
  * [Command verification](#command-verification)
  * [Prompt types](#prompt-types)
  * [Customizing the SSH command](#customizing-the-ssh-command)
  * [Stub location](#stub-location)
* [Building from Source](#building-from-source)
* [Troubleshooting](#troubleshooting)
* [Development](#development)


## Installation
Using SSH Guardian Agent requires installation **both on your local machine** (the
one with your SSH private keys) and on each of the **intermediary machines** you
want to securely forward SSH agent to (the machines on which you want to run an
SSH client without having the keys on them). **No installation is required on the
server side.**

1. Install the following dependencies: OpenSSH client, autossh, ssh-askpass.
2. Obtain the [latest
   release](https://github.com/StanfordSNR/guardian-agent/releases/latest) for
   your platform. Alternatively, you may opt to [build from source](#building).
3. Extract the executables (`sga-guard`, `sga-guard-bin`, `sga-ssh`, and
   `sga-stub`) from the tarball to a **directory in the user's PATH**.

<details><summary>Ubuntu installation</summary><p>

```
sudo apt-get install openssh-client autossh ssh-askpass
curl -L https://api.github.com/repos/StanfordSNR/guardian-agent/releases/latest | grep browser_download_url | grep 'linux' | cut -d'"' -f 4 | xargs curl -Ls | tar xzv
sudo cp sga_linux_amd64/* /usr/local/bin
```

</p>
</details>

<details><summary>macOS installation</summary><p>

```
brew install autossh ssh-askpass
curl -L https://api.github.com/repos/StanfordSNR/guardian-agent/releases/latest | grep browser_download_url | grep 'darwin' | cut -d'"' -f 4 | xargs curl -L | tar xzv
sudo cp sga_darwin_amd64/* /usr/local/bin
```

</p>
</details>

## Basic Usage

Make sure SSH guardian agent is installed on both your local and intermediary machine.

### On your local machine
Start guarded SSH agent forwarding to the intermediary machine:

```
[local]$ sga-guard <intermediary>
```  

You should then expect to see the following message:
```
[local]$ sga-guard <intermediary>
Listening for incoming Guardian Agent requests from aws-ubu...
```

Guarded agent forwarding is now enabled on the intermediary.

### On the intermediary
Connect to the intermediary (e.g., using standard ssh or mosh). 
[Install](#installation) guardian-agent.
To enable several common tools (scp, git, rsync, mosh) to use the guardian agent instead of the default
`ssh` program:
```
[intermediary]$ source sga-env.sh
```
You can also add this line to your `~/.bashrc`/`~.zshrc`/... file on the intermediary hosts.

You can then use `git`, `scp`, `rsync`, `mosh` as you would normally do.

You can also use `sga-ssh` as a drop-in replacement to an ssh client:

```
[intermediary]$ sga-ssh <server> [command]
```


## Advanced Usage

### Command verification

Command verification requires the server to support the `no-more-sessions`
extension. This is extension is present on most openssh servers, but
unfortunately not implemented on other SSH servers (including github). When
executing a command on a server that does not support this extension, only the
idenitity of the intermediary and the identity of the server can be verified
(which is still much better than standard ssh-agent forwarding).

### Prompt types

Guardian agent supports two types of interactive prompts: graphical and
terminal-based. The graphical prompt requires the `DISPLAY` environment variable
to be set to the appropriate X11 server.  
If running in a terminal-only session (in which the `DISPLAY` environment
variable is not set), a textual prompt will be used instead.

### Customizing the SSH command

When using `sga-guard`, the default SSH client on the local machine is used to
set up the connection. This requires `ssh` to be found in the user's `PATH`. To
specify an alternative SSH client or specifying additional argument to the
client, use the `--ssh` command-line flag.

### Stub location

If the `sga-stub` is not installed in the user's `PATH` on the intermediary
machine, its location must be specified when setting up secure agent forwarding
from the local machine:

```
[local]$ sga-guard --stub=<PATH-TO-STUB> <intermediary>
```
## Building from Source
1. [Install go 1.8+](https://golang.org/doc/install)
2. Get and build the sources:
```
go get github.com/StanfordSNR/guardian-agent/...
```
3. Copy the built binaries (`sga-guard-bin`, `sga-ssh`, and `sga-stub`) from `$GOPATH/bin` to a directory in the user's PATH.
4. Copy the scripts `$GOPATH/StanfordSNR/guardian-agent/scripts/sga-guard` and `$GOPATH/StanfordSNR/guardian-agent/scripts/sga-env.sh` to a directory in the user's PATH.

## Troubleshooting

In case of [unexpected behavior](https://en.wikipedia.org/wiki/Bug_(software)), please consider opening an issue in our [issue tracker](https://github.com/StanfordSNR/guardian-agent/issues).
We'd also greatly appreciate if you could run the tool in debug mode by setting the `--debug` and `--logfile=<LOG-FILE>` flags and attach the log file to the issue.

## Development
[Detailed Design](doc/design.md)
