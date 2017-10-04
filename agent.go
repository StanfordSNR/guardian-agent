package guardianagent

import (
	"bytes"
	"crypto/md5"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"strings"

	"path"

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
	policy        Policy
	store         *Store
}

func NewGuardian(policyConfigPath string, inType InputType) (*Agent, error) {
	realAgentPath := os.Getenv("SSH_AUTH_SOCK")
	if realAgentPath == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK not set")
	}

	var ui UI
	switch inType {
	case Terminal:
		if !terminal.IsTerminal(int(os.Stdin.Fd())) {
			return nil, fmt.Errorf("standard input is not a terminal")
		}
		ui = FancyTerminalUI{}
		break
	case Display:
		ui = AskPassUI{}
	}

	// get policy store
	store, err := NewStore(policyConfigPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to load policy store: %s", err)
	}
	return &Agent{
			realAgentPath: realAgentPath,
			store:         store,
			policy:        Policy{Store: store, UI: ui}},
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
		password, err := agent.policy.UI.AskPassword(fmt.Sprintf("Enter passphrase for key '%s':", keyPath))
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

// Adapted from https://github.com/coreos/fleet/blob/master/ssh/known_hosts.go
func putHostKey(knownHostsPath string, addr string, hostKey ssh.PublicKey) error {
	// Make necessary directories if needed
	err := os.MkdirAll(path.Dir(knownHostsPath), 0700)
	if err != nil {
		return err
	}

	out, err := os.OpenFile(knownHostsPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = out.Write(renderHostLine(addr, hostKey))
	if err != nil {
		return err
	}
	return nil
}

func renderHostLine(addr string, key ssh.PublicKey) []byte {
	keyByte := ssh.MarshalAuthorizedKey(key)
	// allocate line space in advance
	length := len(addr) + 1 + len(keyByte)
	line := make([]byte, 0, length)

	w := bytes.NewBuffer(line)
	w.Write([]byte(addr))
	w.WriteByte(' ')
	w.Write(keyByte)
	return w.Bytes()
}

const (
	warningRemoteHostChanged = `@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the %v key sent by the remote host is
%v.
Please contact your system administrator.
Add correct host key in %v to get rid of this message.
Host key verification failed.
	`
	promptToTrustHost = `The authenticity of host '%v' can't be established.
%v key fingerprint is %v.
Are you sure you want to continue connecting (yes/no)? `
)

// md5String returns a formatted string representing the given md5Sum in hex
func md5String(md5Sum [16]byte) string {
	md5Str := fmt.Sprintf("% x", md5Sum)
	md5Str = strings.Replace(md5Str, " ", ":", -1)
	return md5Str
}

func (agent *Agent) hostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	curuser, err := user.Current()
	if err != nil {
		return fmt.Errorf("Failed to get current user: %s", err)
	}
	knownHostsPath := path.Join(curuser.HomeDir, ".ssh", "known_hosts")
	kh, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return err
	}
	err = kh(hostname, remote, key)

	if err == nil {
		return nil
	}

	if _, ok := err.(*knownhosts.RevokedError); ok {
		return err
	}

	keyFingerprintStr := md5String(md5.Sum(key.Marshal()))

	if kErr, ok := err.(*knownhosts.KeyError); ok && len(kErr.Want) > 0 {
		agent.policy.UI.Alert(fmt.Sprintf(warningRemoteHostChanged, key.Type(), keyFingerprintStr, knownHostsPath))
		return kErr
	}

	if agent.policy.UI.Confirm(fmt.Sprintf(promptToTrustHost, hostname, key.Type(), keyFingerprintStr)) {
		return putHostKey(knownHostsPath, knownhosts.Normalize(hostname), key)
	}

	return &knownhosts.KeyError{}
}

func (agent *Agent) proxySSH(scope Scope, toClient net.Conn, toServer net.Conn, control net.Conn, fil *ssh.Filter) error {
	curuser, err := user.Current()
	if err != nil {
		return fmt.Errorf("Failed to get current user: %s", err)
	}
	clientConfig := &ssh.ClientConfig{
		User:            scope.ServiceUsername,
		HostKeyCallback: agent.hostKeyCallback,
		Auth:            []ssh.AuthMethod{agent.getAuth(curuser.HomeDir)},
	}

	meteredConnToServer := CustomConn{Conn: toServer}
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

	remote := false
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
			remote = true
			notice := new(AgentForwardingNoticeMsg)
			if err := ssh.Unmarshal(payload, notice); err != nil {
				return fmt.Errorf("Failed to unmarshal AgentForwardingNoticeMsg: %s", err)
			}
			scope.ClientHostname = notice.Hostname
			scope.ClientPort = notice.Port
			scope.ClientUsername = notice.Username
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
			if remote {
				WriteControlPacket(conn, MsgAgentFailure, []byte{})
				return fmt.Errorf("Denied raw remote access to SSH_AUTH_SOCK ")
			}
			realAgent, err := net.Dial("unix", agent.realAgentPath)
			if err != nil {
				return err
			}
			go func() {
				io.Copy(conn, realAgent)
			}()
			if err = WriteControlPacket(realAgent, msgNum, payload); err != nil {
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
