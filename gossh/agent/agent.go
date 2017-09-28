package agent

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"

	"path"

	"github.com/dimakogan/ssh/gossh/common"
	"github.com/dimakogan/ssh/gossh/policy"
	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/ssh"
	sshAgent "golang.org/x/crypto/ssh/agent"
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
	policy        policy.Policy
	store         *policy.Store
}

func New(policyConfigPath string, inType InputType) (*Agent, error) {
	realAgentPath := os.Getenv("SSH_AUTH_SOCK")
	if realAgentPath == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK not set")
	}

	var interact common.Interact
	switch inType {
	case Terminal:
		if !terminal.IsTerminal(int(os.Stdin.Fd())) {
			return nil, fmt.Errorf("standard input is not a terminal")
		}
		interact = common.FancyTerminal{}
		break
	case Display:
		interact = common.AskPass{}
	}

	// get policy store
	store, err := policy.NewStore(policyConfigPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to load policy store: %s", err)
	}
	return &Agent{
			realAgentPath: realAgentPath,
			store:         store,
			policy:        policy.Policy{Store: store, Interact: interact}},
		nil
}

func (agent *Agent) getKeyFileAuth(keyPath string) (ssh.Signer, error) {
	buf, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	p, rest := pem.Decode(buf)
	if len(rest) > 0 {
		return nil, fmt.Errorf("Failed to decode key")
	}
	pBlock := pem.Block{
		Bytes:   buf,
		Type:    p.Type,
		Headers: p.Headers,
	}
	if x509.IsEncryptedPEMBlock(&pBlock) {
		password, err := agent.policy.Interact.AskPassword(fmt.Sprintf("Enter passphrase for key '%s'", keyPath))
		rawkey, err := ssh.ParsePrivateKeyWithPassphrase(buf, password)
		if err != nil {
			return nil, err
		}
		return rawkey.(ssh.Signer), nil
	}
	// Non-encrypted key
	key, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (agent *Agent) getAuth(homeDir string) ssh.AuthMethod {
	realAgent, err := net.Dial("unix", agent.realAgentPath)
	if err == nil {
		agentClient := sshAgent.NewClient(realAgent)
		agentKeys, err := agentClient.List()
		if err != nil && len(agentKeys) > 0 {
			return ssh.PublicKeysCallback(agentClient.Signers)
		}
	}

	var signers []ssh.Signer
	for _, keyFile := range []string{"identity", "id_dsa", "id_rsa", "id_ecdsa", "id_ed25519"} {
		keyPath := path.Join(homeDir, ".ssh", keyFile)
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			continue
		}
		signer, err := agent.getKeyFileAuth(keyPath)
		if err != nil {
			log.Printf("Error parsing private key: %s: %s", keyPath, err)
			continue
		}
		signers = append(signers, signer)
	}
	return ssh.PublicKeys(signers...)
}

func (agent *Agent) proxySSH(scope policy.Scope, toClient net.Conn, toServer net.Conn, control net.Conn, fil *ssh.Filter) error {

	curuser, err := user.Current()
	if err != nil {
		return fmt.Errorf("Failed to get current user: %s", err)
	}
	kh, err := knownhosts.New(path.Join(curuser.HomeDir, ".ssh", "known_hosts"))
	if err != nil {
		return err
	}
	clientConfig := &ssh.ClientConfig{
		User:            scope.ServiceUsername,
		HostKeyCallback: kh,
		Auth:            []ssh.AuthMethod{agent.getAuth(curuser.HomeDir)},
	}

	meteredConnToServer := common.CustomConn{Conn: toServer}
	proxy, err := ssh.NewProxyConn(scope.ServiceHostname, toClient, &meteredConnToServer, clientConfig, fil)
	if err != nil {
		return err
	}
	err = proxy.UpdateClientSessionParams()
	if err != nil {
		return err
	}

	done := proxy.Run()

	err = <-done
	var msgNum byte
	var msg interface{}
	if err != nil {
		msg = common.HandoffFailedMessage{Msg: err.Error()}
		msgNum = common.MsgHandoffFailed

	} else {
		msg = common.HandoffCompleteMessage{
			NextTransportByte: uint32(meteredConnToServer.BytesRead() - proxy.BufferedFromServer())}
		msgNum = common.MsgHandoffComplete
	}
	packet := ssh.Marshal(msg)
	return common.WriteControlPacket(control, msgNum, packet)
}

func (agent *Agent) HandleConnection(conn net.Conn) error {
	log.Printf("New incoming connection")

	remote := false
	var scope policy.Scope
	for {
		msgNum, payload, err := common.ReadControlPacket(conn)
		if err == io.EOF || err == io.ErrClosedPipe {
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
			scope.ClientHostname = notice.Hostname
			scope.ClientPort = notice.Port
			scope.ClientUsername = notice.Username
		case common.MsgExecutionRequest:
			execReq := new(common.ExecutionRequestMessage)
			if err = ssh.Unmarshal(payload, execReq); err != nil {
				return fmt.Errorf("Failed to unmarshal ExecutionRequestMessage: %s", err)
			}
			scope.ServiceHostname = execReq.Server
			scope.ServiceUsername = execReq.User
			agent.handleExecutionRequest(conn, scope, execReq.Command)
		case common.MsgAgentCExtension:
			queryExtension := new(common.AgentCExtensionMsg)
			ssh.Unmarshal(payload, queryExtension)
			if queryExtension.ExtensionType == common.AgentGuardExtensionType {
				common.WriteControlPacket(conn, common.MsgAgentSuccess, []byte{})
				continue
			}
			fallthrough
		default:
			if remote {
				common.WriteControlPacket(conn, common.MsgAgentFailure, []byte{})
				return fmt.Errorf("Denied raw remote access to SSH_AUTH_SOCK ")
			}
			realAgent, err := net.Dial("unix", agent.realAgentPath)
			if err != nil {
				return err
			}
			go func() {
				io.Copy(conn, realAgent)
			}()
			if err = common.WriteControlPacket(realAgent, msgNum, payload); err != nil {
				return err
			}
			go func() {
				io.Copy(realAgent, conn)
				realAgent.Close()
			}()
			return nil
		}
	}
}

func (agent *Agent) handleExecutionRequest(conn net.Conn, scope policy.Scope, cmd string) error {
	err := agent.policy.RequestApproval(scope, cmd)
	if err != nil {
		common.WriteControlPacket(conn, common.MsgExecutionDenied,
			ssh.Marshal(common.ExecutionDeniedMessage{Reason: err.Error()}))
		return nil
	}
	filter := ssh.NewFilter(cmd, func() error { return agent.policy.RequestApprovalForAllCommands(scope) })
	common.WriteControlPacket(conn, common.MsgExecutionApproved, []byte{})

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

	err = agent.proxySSH(scope, sshData, transport, control, filter)
	transport.Close()
	sshData.Close()
	control.Close()

	if err != nil {
		return fmt.Errorf("Proxy session finished with error: %s", err)
	}

	return nil

}
