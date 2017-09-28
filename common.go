package guardianagent


import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
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
	Hostname string
	IP       string
	Port     uint32
	Username string
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
