package guardianagent

import (
	"crypto/md5"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"path"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

const debugCommon = false

const AgentGuardExtensionType = "agent-guard@cs.stanford.edu"

const AgentGuardSockName = ".agent-guard-sock"

const MsgAgentSuccess = 6

const MsgAgentFailure = 5

type AgentFailureMsg struct{}

const MsgAgentCExtension = 27

type AgentCExtensionMsg struct {
	ExtensionType string
	Contents      []byte
}

const MsgAgentForwardingNotice = 206

type AgentForwardingNoticeMsg struct {
	Client string
}

const MsgExecutionRequest = 1
const MsgExecutionDenied = 2
const MsgExecutionApproved = 3
const MsgHandoffComplete = 10
const MsgHandoffFailed = 11

const MaxAgentPacketSize = 10 * 1024

type ExecutionApprovedMessage struct {
}

type ExecutionDeniedMessage struct {
	Reason string
}

type ExecutionRequestMessage struct {
	User    string
	Command string
	Server  string
}

type HandoffCompleteMessage struct {
	NextTransportByte uint32
}

type HandoffFailedMessage struct {
	Msg string
}

type CustomConn struct {
	net.Conn
	RemoteAddress net.Addr
	bytesRead     int
	bytesWritten  int
}

func (cc *CustomConn) RemoteAddr() net.Addr {
	if cc.RemoteAddress != nil {
		return cc.RemoteAddress
	}
	return cc.Conn.RemoteAddr()
}

func (cc *CustomConn) BytesRead() int {
	return cc.bytesRead
}

func (cc *CustomConn) BytesWritten() int {
	return cc.bytesWritten
}

func (cc *CustomConn) Read(p []byte) (n int, err error) {
	n, err = cc.Conn.Read(p)
	cc.bytesRead += n
	return
}

func (cc *CustomConn) Write(b []byte) (n int, err error) {
	n, err = cc.Conn.Write(b)
	cc.bytesWritten += n
	return
}

func ReadControlPacket(r io.Reader) (msgNum byte, payload []byte, err error) {
	var packetLenBytes [4]byte
	_, err = io.ReadFull(r, packetLenBytes[:])
	if err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(packetLenBytes[:])
	if debugCommon {
		log.Printf("read len bytes: %s, len: %d", hex.EncodeToString(packetLenBytes[:]), length)
	}
	payload = make([]byte, length)
	_, err = io.ReadFull(r, payload[:])
	if debugCommon {
		log.Printf("read: %s", hex.EncodeToString(payload[:]))
	}

	return payload[0], payload[1:], err
}

func WriteControlPacket(w io.Writer, msgNum byte, payload []byte) error {
	var packetHeader [5]byte
	binary.BigEndian.PutUint32(packetHeader[:], uint32(len(payload)+1))
	packetHeader[4] = msgNum
	if debugCommon {
		log.Printf("written len: %d", len(payload)+1)
	}
	if _, err := w.Write(packetHeader[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func ReplaceSSHAuthSockEnv(env []string, newVal string) (newEnv []string, err error) {
	i := 0
	for i = 0; i < len(env); i++ {
		if strings.HasPrefix(env[i], "SSH_AUTH_SOCK") {
			break
		}
	}
	if i == len(env) {
		return nil, fmt.Errorf("No SSH_AUTH_SOCKET defined.")
	}
	env[i] = fmt.Sprintf("%s=%s", "SSH_AUTH_SOCK", newVal)
	return env, nil
}

func UserTempDir() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir != "" {
		return dir
	}
	dir, err := ioutil.TempDir("", "")
	if err == nil {
		return dir
	}
	return os.Getenv("HOME")
}

func UserRuntimeDir() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir != "" {
		return dir
	}
	return os.Getenv("HOME")
}

type CommonOptions struct {
	Debug bool `long:"debug" description:"Show debug information"`

	Username string `short:"l" description:"Specifies the user to log in as on the remote machine"`

	LogFile string `long:"log" description:"log file"`
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

	_, err = fmt.Fprintln(out, renderHostLine(addr, hostKey))
	if err != nil {
		return err
	}
	return nil
}

func renderHostLine(addr string, key ssh.PublicKey) string {
	return knownhosts.HashHostname(addr) + " " + string(ssh.MarshalAuthorizedKey(key))
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

func HostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey, ui UI) error {
	curuser, err := user.Current()
	if err != nil {
		return fmt.Errorf("Failed to get current user: %s", err)
	}
	keyFingerprintStr := md5String(md5.Sum(key.Marshal()))
	knownHostsPath := path.Join(curuser.HomeDir, ".ssh", "known_hosts")
	if kh, err := knownhosts.New(knownHostsPath); err == nil {
		if err = kh(hostname, remote, key); err == nil {
			return nil
		}

		if _, ok := err.(*knownhosts.RevokedError); ok {
			return err
		}

		if kErr, ok := err.(*knownhosts.KeyError); ok && len(kErr.Want) > 0 {
			ui.Alert(fmt.Sprintf(warningRemoteHostChanged, key.Type(), keyFingerprintStr, knownHostsPath))
			return kErr
		}
	}

	if ui.Confirm(fmt.Sprintf(promptToTrustHost, hostname, key.Type(), keyFingerprintStr)) {
		return putHostKey(knownHostsPath, knownhosts.Normalize(hostname), key)
	}

	return &knownhosts.KeyError{}
}

func getKeyFileAuth(keyPath string, ui UI) (ssh.Signer, error) {
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
		password, err := ui.AskPassword(fmt.Sprintf("Enter passphrase for key '%s':", keyPath))
		rawkey, err := ssh.ParsePrivateKeyWithPassphrase(buf, []byte(password))
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

func getAuth(username string, host string, homeDir string, ui UI) []ssh.AuthMethod {
	passwordAuthMethod := ssh.PasswordCallback(func() (string, error) {
		return ui.AskPassword(fmt.Sprintf("%s@%s password:", username, host))
	})
	realAgentPath := os.Getenv("SSH_AUTH_SOCK")
	if realAgentPath != "" {
		realAgent, err := net.Dial("unix", realAgentPath)
		if err == nil {
			agentClient := agent.NewClient(realAgent)
			agentKeys, err := agentClient.List()
			if err == nil && len(agentKeys) > 0 {
				return []ssh.AuthMethod{
					ssh.PublicKeysCallback(agentClient.Signers),
					passwordAuthMethod,
				}
			}
		}
	}

	var signers []ssh.Signer
	for _, keyFile := range []string{"identity", "id_dsa", "id_rsa", "id_ecdsa", "id_ed25519"} {
		keyPath := path.Join(homeDir, ".ssh", keyFile)
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			continue
		}
		signer, err := getKeyFileAuth(keyPath, ui)
		if err != nil {
			log.Printf("Error parsing private key: %s: %s", keyPath, err)
			continue
		}
		signers = append(signers, signer)
	}
	return []ssh.AuthMethod{ssh.PublicKeys(signers...), passwordAuthMethod}
}
