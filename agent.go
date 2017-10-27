package guardianagent

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path"

	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/crypto/ssh/terminal"
)

type InputType uint8

const (
	Terminal = iota
	Display
)

type Agent struct {
	policy Policy
	store  *Store
}

func NewGuardian(policyConfigPath string, inType InputType) (*Agent, error) {
	var ui UI
	switch inType {
	case Terminal:
		if !terminal.IsTerminal(int(os.Stdin.Fd())) {
			return nil, fmt.Errorf("standard input is not a terminal")
		}
		ui = &FancyTerminalUI{}
		break
	case Display:
		ui = &AskPassUI{}
	}

	// get policy store
	store, err := NewStore(policyConfigPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to load policy store: %s", err)
	}
	return &Agent{
			store:  store,
			policy: Policy{Store: store, UI: ui}},
		nil
}

func (agent *Agent) proxySSH(scope Scope, toClient net.Conn, toServer net.Conn, control net.Conn, fil *ssh.Filter) error {
	curuser, err := user.Current()
	if err != nil {
		return fmt.Errorf("Failed to get current user: %s", err)
	}

	clientConfig := &ssh.ClientConfig{
		User: scope.ServiceUsername,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return HostKeyCallback(hostname, remote, key, agent.policy.UI)
		},
		Auth:              getAuth(scope.ServiceUsername, scope.ServiceHostname, curuser.HomeDir, agent.policy.UI),
		HostKeyAlgorithms: knownhosts.OrderHostKeyAlgs(scope.ServiceHostname, toServer.RemoteAddr(), path.Join(curuser.HomeDir, ".ssh", "known_hosts")),
	}

	meteredConnToServer := CustomConn{Conn: toServer}
	proxy, err := ssh.NewProxyConn(scope.ServiceHostname, toClient, &meteredConnToServer, clientConfig, fil)
	if err != nil {
		return err
	}
	done := proxy.Run()

	err = <-done
	var msgNum byte
	var msg interface{}
	if err != nil {
		msg = HandoffFailedMessage{Msg: err.Error()}
		msgNum = MsgHandoffFailed

	} else {
		msg = HandoffCompleteMessage{
			NextTransportByte: uint32(meteredConnToServer.BytesRead() - proxy.BufferedFromServer())}
		msgNum = MsgHandoffComplete
	}
	packet := ssh.Marshal(msg)
	return WriteControlPacket(control, msgNum, packet)
}

func (agent *Agent) HandleConnection(conn net.Conn) error {
	log.Printf("New incoming connection")

	var scope Scope
	for {
		msgNum, payload, err := ReadControlPacket(conn)
		if err == io.EOF || err == io.ErrClosedPipe {
			return nil
		}
		if err != nil {
			return fmt.Errorf("Failed to read control packet: %s", err)
		}
		switch msgNum {
		case MsgAgentForwardingNotice:
			notice := new(AgentForwardingNoticeMsg)
			if err := ssh.Unmarshal(payload, notice); err != nil {
				return fmt.Errorf("Failed to unmarshal AgentForwardingNoticeMsg: %s", err)
			}
			scope.Client = notice.Client
		case MsgExecutionRequest:
			execReq := new(ExecutionRequestMessage)
			if err = ssh.Unmarshal(payload, execReq); err != nil {
				return fmt.Errorf("Failed to unmarshal ExecutionRequestMessage: %s", err)
			}
			scope.ServiceHostname = execReq.Server
			scope.ServiceUsername = execReq.User
			agent.handleExecutionRequest(conn, scope, execReq.Command)
		case MsgAgentCExtension:
			queryExtension := new(AgentCExtensionMsg)
			ssh.Unmarshal(payload, queryExtension)
			if queryExtension.ExtensionType == AgentGuardExtensionType {
				WriteControlPacket(conn, MsgAgentSuccess, []byte{})
				continue
			}
			fallthrough
		default:
			WriteControlPacket(conn, MsgAgentFailure, []byte{})
			return fmt.Errorf("Unrecognized incoming message: %d", msgNum)
		}
	}
}

func (ag *Agent) handleExecutionRequest(conn net.Conn, scope Scope, cmd string) error {
	err := ag.policy.RequestApproval(scope, cmd)
	if err != nil {
		WriteControlPacket(conn, MsgExecutionDenied,
			ssh.Marshal(ExecutionDeniedMessage{Reason: err.Error()}))
		return nil
	}
	filter := ssh.NewFilter(cmd, func() error { return ag.policy.RequestApprovalForAllCommands(scope) })
	WriteControlPacket(conn, MsgExecutionApproved, []byte{})

	ymux, err := yamux.Server(conn, nil)
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

	err = ag.proxySSH(scope, sshData, transport, control, filter)
	transport.Close()
	sshData.Close()
	control.Close()

	if err != nil {
		return fmt.Errorf("Proxy session finished with error: %s", err)
	}

	return nil

}
