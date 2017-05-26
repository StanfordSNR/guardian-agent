package main

import (
	"bufio"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"

	"path"

	"fmt"

	"github.com/dimakogan/ssh/gossh/common"
	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

type policyStore map[[32]byte]bool

func proxySSH(toClient net.Conn, toServer net.Conn, control net.Conn, pc *ssh.Policy) error {
	var auths []ssh.AuthMethod
	aconn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return err
	}

	auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(aconn).Signers))

	if err != nil {
		return err
	}

	curuser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %s", err)
	}
	kh, err := knownhosts.New(path.Join(curuser.HomeDir, ".ssh", "known_hosts"))
	if err != nil {
		return err
	}
	clientConfig := &ssh.ClientConfig{
		User:            pc.User,
		HostKeyCallback: kh,
		Auth:            auths,
	}

	meteredConnToServer := common.CustomConn{Conn: toServer}
	proxy, err := ssh.NewProxyConn(pc.Server, toClient, &meteredConnToServer, clientConfig, pc.FilterClientPacket, pc.FilterServerPacket)
	if err != nil {
		return err
	}
	err = proxy.UpdateClientSessionParams()
	if err != nil {
		return err
	}

	done := proxy.Run()

	err = <-done
	if err != nil {
		return err
	}

	handshakeCompletedMsg := common.HandoffCompleteMessage{
		NextTransportByte: uint32(meteredConnToServer.BytesRead() - proxy.BufferedFromServer()),
	}
	packet := ssh.Marshal(handshakeCompletedMsg)
	return common.WriteControlPacket(control, common.MsgHandoffComplete, packet)
}

func terminalPrompt(text string) (reply string, err error) {
	fmt.Print(text)
	reader := bufio.NewReader(os.Stdin)
	return reader.ReadString('\n')
}

func askPassPrompt(text string) (reply string, err error) {
	cmd := exec.Command("ssh-askpass", text)
	out, err := cmd.Output()
	return string(out), err
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	f, err := os.OpenFile("/tmp/ssh-guard.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)
	var bindAddr string
	flag.StringVar(&bindAddr, "a", "", "Address to bind to. Default is /tmp/ssh-guard-XXXXXXXXXX/agent.<ppid>")
	flag.Parse()
	masterListener, bindAddr, err := common.CreateSocket(bindAddr)
	if err != nil {
		log.Fatalf("Failed to listen on socket %s: %s", bindAddr, err)
	}

	log.Printf("Listening on: %s", bindAddr)
	defer masterListener.Close()
	defer os.Remove(bindAddr)

	// can and should be refactored if we do one agent in all rather than one per connection
	// Similarly, if we choose to enable a mode to remember per command approval (rather than all commands)
	// should make it map to an array of commands, with a wildcard to signify all.
	store := make(policyStore)
	args := flag.Args()
	promptFunc := terminalPrompt
	stopped := false

	if flag.NArg() > 0 {
		child := exec.Command(args[0], args[1:]...)
		env, err := common.ReplaceSSHAuthSockEnv(os.Environ(), bindAddr)
		if err != nil {
			log.Fatal(err)
		}
		child.Env = env

		child.Stdin = os.Stdin
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err = child.Start(); err != nil {
			log.Fatalf("Failed to execute child process: %s", err)
		}
		go func() {
			if err = child.Wait(); err != nil {
				log.Fatalf("Failed to execute child process: %s", err)
			}
			stopped = true
			masterListener.Close()
		}()
		promptFunc = askPassPrompt
	} else {
		fmt.Printf("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", bindAddr)
		fmt.Printf("SSH_AGENT_PID=%d; export SSH_AGENT_PID;\n", os.Getpid())
		fmt.Printf("echo Agent pid %d;\n", os.Getpid())
	}

	for {
		master, err := masterListener.Accept()
		if stopped {
			break
		}
		if err != nil {
			log.Fatalf("Failed to accept connection: %s", err)
			return
		}
		if err = handleConnection(master, store, promptFunc); err != nil {
			log.Printf("Error handling connection: %s", err)
		}
	}
}

func handleConnection(master net.Conn, store policyStore, promptFunc ssh.PromptUserFunc) error {
	log.Printf("New incoming connection")
	policy := ssh.Policy{Prompt: promptFunc}

	var err error
	gotRequest := false
	for err == nil && !gotRequest {
		msgNum, payload, err := common.ReadControlPacket(master)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("Failed to read control packet: %s", err)
		}
		switch msgNum {
		case common.MsgAgentForwardingNotice:
			notice := new(common.AgentForwardingNoticeMsg)
			if err := ssh.Unmarshal(payload, notice); err != nil {
				return fmt.Errorf("Failed to unmarshal AgentForwardingNoticeMsg: %s", err)
			}
			policy.ClientHostname = notice.Hostname
			policy.ClientPort = notice.Port
			policy.ClientUsername = notice.Username
		case common.MsgExecutionRequest:
			execReq := new(common.ExecutionRequestMessage)
			if err = ssh.Unmarshal(payload, execReq); err != nil {
				return fmt.Errorf("Failed to unmarshal ExecutionRequestMessage: %s", err)
			}
			policy.User = execReq.User
			policy.Command = execReq.Command
			policy.Server = execReq.Server
			gotRequest = true
		default:
			realAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
			if err != nil {
				log.Fatal(err)
			}
			go func() {
				io.Copy(master, realAgent)
				master.Close()
			}()
			if err = common.WriteControlPacket(realAgent, msgNum, payload); err != nil {
				return err
			}
			go func() {
				io.Copy(realAgent, master)
				realAgent.Close()
			}()
			return nil
		}
	}

	// to be changed if per command approval enabled
	_, policyStored := store[policy.GetPolicyID()]
	if !policyStored {
		err = policy.AskForApproval(store)
		if err != nil {
			common.WriteControlPacket(master, common.MsgExecutionDenied, []byte{})
			return fmt.Errorf("Request denied: %s", err)
		}
	}
	common.WriteControlPacket(master, common.MsgExecutionApproved, []byte{})

	ymux, err := yamux.Server(master, nil)
	if err != nil {
		master.Close()
		return fmt.Errorf("Failed to start ymux: %s", err)
	}
	defer ymux.Close()

	control, err := ymux.Accept()
	if err != nil {
		return fmt.Errorf("Failed to accept control stream: %s", err)
	}
	defer control.Close()

	sshData, err := ymux.Accept()
	if err != nil {
		return fmt.Errorf("Failed to accept data stream: %s", err)
	}
	defer sshData.Close()

	transport, err := ymux.Accept()
	if err != nil {
		return fmt.Errorf("Failed to get transport stream: %s", err)
	}
	defer transport.Close()

	err = proxySSH(sshData, transport, control, &policy)
	transport.Close()
	sshData.Close()
	control.Close()
	// Wait for client to close master connection
	ioutil.ReadAll(master)

	if err != nil {
		return fmt.Errorf("Proxy session finished with error: %s", err)
	}
	log.Print("Session complete OK")
	return nil
}
