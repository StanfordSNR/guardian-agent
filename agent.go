package guardianagent

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path"

	"github.com/golang/protobuf/proto"

	"github.com/StanfordSNR/guardian-agent/guardo"
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
	var msgNum MsgNum
	var msg interface{}
	if err != nil {
		msg = HandoffFailedMessage{Msg: err.Error()}
		msgNum = MsgNum_HANDOFF_FAILED

	} else {
		msg = HandoffCompleteMessage{
			NextTransportByte: uint32(meteredConnToServer.BytesRead() - proxy.BufferedFromServer())}
		msgNum = MsgNum_HANDOFF_COMPLETE
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
		log.Printf("Got msgNum: %d", msgNum)
		switch msgNum {
		case MsgNum_AGENT_FORWARDING_NOTICE:
			notice := new(AgentForwardingNoticeMsg)
			if err := ssh.Unmarshal(payload, notice); err != nil {
				return fmt.Errorf("Failed to unmarshal AgentForwardingNoticeMsg: %s", err)
			}
			scope.Client = notice.Client
		case MsgNum_EXECUTION_REQUEST:
			execReq := new(ExecutionRequestMessage)
			if err = ssh.Unmarshal(payload, execReq); err != nil {
				return fmt.Errorf("Failed to unmarshal ExecutionRequestMessage: %s", err)
			}
			scope.ServiceHostname = execReq.Server
			scope.ServiceUsername = execReq.User
			agent.handleExecutionRequest(conn, scope, execReq.Command)
		case MsgNum_CREDENTIAL_REQUEST:
			credReq := new(guardo.CredentialRequest)
			if err = proto.Unmarshal(payload, credReq); err != nil {
				return fmt.Errorf("Failed to unmarshal CredentialRequest: %s", err)
			}
			log.Printf("Got credential request: %v", credReq)
			agent.handleCredentialRequest(conn, scope, credReq)
		case MsgNum_AGENTC_EXTENSION:
			queryExtension := new(AgentCExtensionMsg)
			ssh.Unmarshal(payload, queryExtension)
			if queryExtension.ExtensionType == AgentGuardExtensionType {
				WriteControlPacket(conn, MsgNum_AGENT_SUCCESS, []byte{})
				continue
			}
			fallthrough
		default:
			WriteControlPacket(conn, MsgNum_AGENT_FAILURE, []byte{})
			return fmt.Errorf("Unrecognized incoming message: %d", msgNum)
		}
	}
}

func (agent *Agent) handleExecutionRequest(conn net.Conn, scope Scope, cmd string) error {
	err := agent.policy.RequestApproval(scope, cmd)
	if err != nil {
		WriteControlPacket(conn, MsgNum_EXECUTION_DENIED,
			ssh.Marshal(ExecutionDeniedMessage{Reason: err.Error()}))
		return nil
	}
	filter := ssh.NewFilter(cmd, func() error { return agent.policy.RequestApprovalForAllCommands(scope) })
	WriteControlPacket(conn, MsgNum_EXECUTION_APPROVED, []byte{})

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

func (agent *Agent) handleCredentialRequest(conn net.Conn, scope Scope, req *guardo.CredentialRequest) error {
	resp := agent.buildCredentialResponse(scope, req)
	log.Printf("Credential Response: %v", resp)
	bytes, err := proto.Marshal(resp)
	if err != nil {
		log.Printf("Failed to marshal credential response: %s, %v", err, resp)
	}
	WriteControlPacket(conn, MsgNum_CREDENTIAL_RESPONSE, bytes)
	return nil
}

func (agent *Agent) buildCredentialResponse(scope Scope, req *guardo.CredentialRequest) *guardo.CredentiallResponse {
	resp := &guardo.CredentiallResponse{}
	err := agent.policy.RequestCredential(scope, req)
	if err != nil {
		resp.Status = guardo.CredentiallResponse_DENIED
		return resp
	}
	resp.Credential = &guardo.Credential{Op: req.GetOp()}
	err = agent.signCredential(resp.Credential)
	if err != nil {
		resp.Status = guardo.CredentiallResponse_ERROR
		return resp
	}

	resp.Status = guardo.CredentiallResponse_APPROVED
	return resp
}

func (agent *Agent) signCredential(cred *guardo.Credential) error {
	curuser, err := user.Current()
	if err != nil {
		return fmt.Errorf("Failed to get current user: %s", err)
	}
	signers := getSigners(curuser.HomeDir, agent.policy.UI)
	signer := signers[0]
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	cred.SignerNonce = nonce
	cred.SignatureKey = signer.PublicKey().Marshal()

	sig, err := signer.Sign(rand.Reader, []byte(cred.String()))
	if err != nil {
		return err
	}
	cred.Signature = sig.Blob
	cred.SignatureFormat = sig.Format
	return nil
}
