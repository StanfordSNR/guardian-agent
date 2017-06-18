package agent

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"

	"path"

	"github.com/dimakogan/ssh/gossh/common"
	"github.com/dimakogan/ssh/gossh/policy"
	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/crypto/ssh/terminal"
)

type InputType uint8

const (
	Terminal = iota
	Display
)

type Agent struct {
	realAgentPath string
	promptFunc    common.PromptUserFunc
	store         policy.Store
}

func New(policyConfigPath string, inType InputType) (*Agent, error) {
	realAgentPath := os.Getenv("SSH_AUTH_SOCK")
	if realAgentPath == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK not set")
	}

	var promptFunc common.PromptUserFunc
	switch inType {
	case Terminal:
		if !terminal.IsTerminal(int(os.Stdin.Fd())) {
			return nil, fmt.Errorf("stanard input is not a terminal")
		}
		promptFunc = common.FancyTerminalPrompt
		break
	case Display:
		promptFunc = common.AskPassPrompt
	}

	// get policy store
	err, store := policy.NewStore(policyConfigPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to load policy store: %s", err)
	}
	return &Agent{
			realAgentPath: realAgentPath,
			promptFunc:    promptFunc,
			store:         store},
		nil
}

func (a *Agent) proxySSH(toClient net.Conn, toServer net.Conn, control net.Conn, fil *ssh.Filter) error {
	var auths []ssh.AuthMethod

	realAgent, err := net.Dial("unix", a.realAgentPath)
	if err != nil {
		return err
	}

	auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(realAgent).Signers))

	curuser, err := user.Current()
	if err != nil {
		return fmt.Errorf("Failed to get current user: %s", err)
	}
	kh, err := knownhosts.New(path.Join(curuser.HomeDir, ".ssh", "known_hosts"))
	if err != nil {
		return err
	}
	clientConfig := &ssh.ClientConfig{
		User:            fil.Scope.ServiceUsername,
		HostKeyCallback: kh,
		Auth:            auths,
	}

	meteredConnToServer := common.CustomConn{Conn: toServer}
	proxy, err := ssh.NewProxyConn(fil.Scope.ServiceHostname, toClient, &meteredConnToServer, clientConfig, fil.FilterClientPacket, fil.FilterServerPacket)
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

func (agent *Agent) HandleConnection(master net.Conn) error {
	log.Printf("New incoming connection")

	var err error
	gotRequest := false
	remote := false
	var fCH, fCU, fSH, fSU, fC string
	var fCP uint32
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
			remote = true
			notice := new(common.AgentForwardingNoticeMsg)
			if err := ssh.Unmarshal(payload, notice); err != nil {
				return fmt.Errorf("Failed to unmarshal AgentForwardingNoticeMsg: %s", err)
			}
			fCH = notice.Hostname
			fCP = notice.Port
			fCU = notice.Username
		case common.MsgExecutionRequest:
			execReq := new(common.ExecutionRequestMessage)
			if err = ssh.Unmarshal(payload, execReq); err != nil {
				return fmt.Errorf("Failed to unmarshal ExecutionRequestMessage: %s", err)
			}
			fSU = execReq.User
			fC = execReq.Command
			fSH = execReq.Server
			gotRequest = true
		case common.MsgAgentCExtension:
			queryExtension := new(common.AgentCExtensionMsg)
			ssh.Unmarshal(payload, queryExtension)
			if queryExtension.ExtensionType == common.AgentGuardExtensionType {
				common.WriteControlPacket(master, common.MsgAgentSuccess, []byte{})
				continue
			}
			fallthrough
		default:
			if remote {
				common.WriteControlPacket(master, common.MsgAgentFailure, []byte{})
				return fmt.Errorf("Denied raw remote access to SSH_AUTH_SOCK ")
			}
			realAgent, err := net.Dial("unix", agent.realAgentPath)
			if err != nil {
				return err
			}
			go func() {
				io.Copy(master, realAgent)
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

	filter := ssh.NewFilter(policy.Scope{fCU, fCH, fCP, fSU, fSH}, agent.store, fC, agent.promptFunc)

	if err = filter.IsApproved(); err != nil {
		common.WriteControlPacket(master, common.MsgExecutionDenied,
			ssh.Marshal(common.ExecutionDeniedMessage{Reason: err.Error()}))
		return nil
	}
	common.WriteControlPacket(master, common.MsgExecutionApproved, []byte{})

	ymux, err := yamux.Server(master, nil)
	if err != nil {
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

	err = agent.proxySSH(sshData, transport, control, filter)
	transport.Close()
	sshData.Close()
	control.Close()

	if err != nil {
		return fmt.Errorf("Proxy session finished with error: %s", err)
	}

	return nil
}
