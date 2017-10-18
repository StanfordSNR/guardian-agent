package guardianagent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"sync"

	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

const debugClient = true

type DelegatedClient struct {
	HostPort     string
	Username     string
	Cmd          string
	ProxyCommand string
	StdinNull    bool
	ForceTty     bool

	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	stderr  io.Reader
}

func findGuardSocket() (string, error) {
	locations := []string{os.Getenv("SSH_AUTH_SOCK"), path.Join(UserRuntimeDir(), AgentGuardSockName)}
	for _, loc := range locations {
		sock, err := net.Dial("unix", loc)
		if err != nil {
			continue
		}
		defer sock.Close()
		query := AgentCExtensionMsg{
			ExtensionType: AgentGuardExtensionType,
		}

		err = WriteControlPacket(sock, MsgAgentCExtension, ssh.Marshal(query))
		if err != nil {
			continue
		}

		msgNum, _, err := ReadControlPacket(sock)
		if err == nil && msgNum == MsgAgentSuccess {
			sock.Close()
			return loc, nil
		}
	}
	return "", os.ErrNotExist
}

type settableWriter struct {
	w    io.Writer
	mu   sync.Mutex
	werr error
}

func (sw *settableWriter) Write(p []byte) (n int, err error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	if sw.w == nil {
		return 0, errors.New("Writer is closed")
	}

	var wn int
	wn, sw.werr = sw.w.Write(p)
	return wn, sw.werr
}

func (sw *settableWriter) Close() error {
	v, ok := sw.w.(io.Closer)
	if ok {
		return v.Close()
	}
	return nil
}

func (dc *DelegatedClient) startCommand(conn *ssh.Client, cmd string) (err error) {
	// TODO(dimakogan): initial window size should be set to probably 0, to avoid large amounts
	// of data to be transfered through agent prior to handoff.
	dc.session, err = conn.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %s", err)
	}

	dc.stdin, err = dc.session.StdinPipe()
	if err != nil {
		dc.session.Close()
		return fmt.Errorf("failed to setup stdin: %s", err)
	}
	dc.stdout, err = dc.session.StdoutPipe()
	if err != nil {
		dc.session.Close()
		return fmt.Errorf("failed to setup stdout: %s", err)
	}

	dc.stderr, err = dc.session.StderrPipe()
	if err != nil {
		dc.session.Close()
		return fmt.Errorf("failed to setup stderr: %s", err)
	}

	if cmd == "" || dc.ForceTty {
		// Set up terminal modes
		modes := ssh.TerminalModes{
			ssh.ECHO: 0, // disable echoing
		}
		w, h, err := terminal.GetSize(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("failed to get terminal size: %s", err)
		}
		// Request pseudo terminal
		if err := dc.session.RequestPty(os.Getenv("TERM"), h, w, modes); err != nil {
			return fmt.Errorf("request for pseudo terminal failed: %s", err)
		}
	}
	if cmd == "" {
		err = dc.session.Shell()
	} else {
		err = dc.session.Start(cmd)
	}
	if err != nil {
		dc.session.Close()
		return err
	}

	return nil
}

func (dc *DelegatedClient) resume() error {
	defer dc.session.Close()
	go func() {
		if !dc.StdinNull {
			io.Copy(dc.stdin, os.Stdin)
		}
		dc.stdin.Close()
	}()
	done := make(chan error)
	go func() {
		_, err := io.Copy(os.Stdout, dc.stdout)
		done <- err
	}()
	go func() {
		_, err := io.Copy(os.Stderr, dc.stderr)
		done <- err
	}()

	errExec := dc.session.Wait()
	errOut1 := <-done
	errOut2 := <-done
	if errExec != nil {
		return errExec
	}
	if errOut1 != nil {
		return errOut1
	}
	return errOut2
}

func getHandoffNextTransportByte(control net.Conn) (uint32, error) {
	msgNum, handoffPacket, err := ReadControlPacket(control)
	if err != nil {
		return 0, fmt.Errorf("failed to read control packet from agent: %s", err)
	}
	handoffMsg := new(HandoffCompleteMessage)
	switch msgNum {
	case MsgHandoffComplete:
		if err = ssh.Unmarshal(handoffPacket, handoffMsg); err != nil {
			return 0, fmt.Errorf("failed to unmarshal MsgHandshakeCompleted: %s", err)
		}
	case MsgHandoffFailed:
		handoffFailedMsg := new(HandoffFailedMessage)
		ssh.Unmarshal(handoffPacket, handoffFailedMsg)
		if debugClient {
			log.Printf("Handoff Failed: %s", handoffFailedMsg.Msg)
		}
		return 0, errors.New(handoffFailedMsg.Msg)
	default:
		return 0, fmt.Errorf("unexpected msg: %d, when expecting MsgHandshakeCompleted", handoffPacket[0])
	}

	if debugClient {
		log.Printf("Got handoffMsg.NextTransportByte: %d", handoffMsg.NextTransportByte)
	}
	return handoffMsg.NextTransportByte, nil
}

func syncBufferedTraffic(bufferedTraffic *bytes.Buffer, bufferedOffset int, handoffByte uint32) error {
	backfillPos := int(handoffByte) - bufferedOffset
	if backfillPos > bufferedTraffic.Len() {
		return fmt.Errorf(
			"unexpected backfill pos, latest read from server: %d, latest reported by agent: %d",
			bufferedOffset+bufferedTraffic.Len(), handoffByte)
	}
	if backfillPos == bufferedTraffic.Len() {
		if debugClient {
			log.Printf("No backfill necessary")
		}
		bufferedTraffic.Reset()
		return nil
	}
	if backfillPos < 0 {
		return fmt.Errorf("missing bytes to backfill: %d", backfillPos)
	}
	bufferedTraffic.Next(backfillPos)
	return nil
}

// Run starts a delegated session.
func (dc *DelegatedClient) Run() error {
	var err error
	var serverReader io.ReadCloser
	var serverWriter io.WriteCloser
	if dc.ProxyCommand != "" {
		proxyChild := exec.Command(os.Getenv("SHELL"), "-c", "exec "+dc.ProxyCommand)

		proxyChild.Stderr = os.Stderr
		serverReader, err = proxyChild.StdoutPipe()
		if err != nil {
			return fmt.Errorf("failed to get stdout pipe of ProxyCommand process: %s", err)
		}
		serverWriter, err = proxyChild.StdinPipe()
		if err != nil {
			return fmt.Errorf("failed to get stdin pipe of ProxyCommand process: %s", err)
		}

		if err := proxyChild.Start(); err != nil {
			return fmt.Errorf("failed to run ProxyCommand %s: %s", dc.ProxyCommand, err)
		}

		go func() {
			proxyChild.Wait()
		}()
	} else {
		serverConn, err := net.Dial("tcp", dc.HostPort)
		if err != nil {
			return fmt.Errorf("failed to connect to %s: %s", dc.HostPort, err)
		}
		defer serverConn.Close()
		serverReader = serverConn
		serverWriter = serverConn
	}

	guardSock, err := findGuardSocket()
	if err != nil {
		return fmt.Errorf("failed to connect to agent guard: %s.\nDid you setup agent guard forwarding to this host?", err)
	}
	master, err := net.Dial("unix", guardSock)
	if err != nil {
		return fmt.Errorf("Failed to connect to agent guard: %s.\nDid you setup agent guard forwarding to this host?", err)
	}
	defer master.Close()

	execReq := ExecutionRequestMessage{
		User:    dc.Username,
		Command: dc.Cmd,
		Server:  dc.HostPort,
	}

	execReqPacket := ssh.Marshal(execReq)
	err = WriteControlPacket(master, MsgExecutionRequest, execReqPacket)
	if err != nil {
		return fmt.Errorf("failed to send MsgExecutionRequest to agent: %s", err)
	}

	// Wait for response before opening data connection
	msgNum, msg, err := ReadControlPacket(master)
	if err != nil {
		return fmt.Errorf("failed to get approval from agent: %s", err)
	}
	switch msgNum {
	case MsgExecutionApproved:
		break
	case MsgExecutionDenied:
		var denyMsg ExecutionDeniedMessage
		ssh.Unmarshal(msg, &denyMsg)
		return fmt.Errorf("execution denied by agent: %s", denyMsg.Reason)
	default:
		return fmt.Errorf("failed to get approval from agent, unknown reply: %d", msgNum)
	}

	ymux, err := yamux.Client(master, nil)
	defer ymux.Close()
	control, err := ymux.Open()
	if err != nil {
		return fmt.Errorf("failed to get control stream: %s", err)
	}
	defer control.Close()
	// Proceed with approval
	agentData, err := ymux.Open()
	if err != nil {
		return fmt.Errorf("failed to get data stream: %s", err)
	}
	defer agentData.Close()

	pt, err := ymux.Open()
	if err != nil {
		return fmt.Errorf("failed to get transport stream: %s", err)
	}
	agentTransport := CustomConn{Conn: pt}
	defer agentTransport.Close()

	sshClientConn, sshPipe := net.Pipe()

	// Initially, the SSH connection is wired to the agent data,
	// and the server connection is wired to the agent transport.
	sshOut := settableWriter{w: agentData}
	serverOut := settableWriter{w: &agentTransport}
	// To be used to buffer traffic that needs to be replayed to the client
	// after the handoff (since the transport layer might deliver to the agent
	// packets that the server has sent after msgNewKeys).
	bufferedTraffic := new(bytes.Buffer)
	bufferedOffset := 0

	go func() {
		_, err := io.Copy(&sshOut, sshPipe)
		if err != nil {
			log.Printf("Error copying outgoing SSH data: %s", err)
		} else {
			log.Printf("Finished copying outgoing SSH data")
		}
		sshOut.Close()
	}()

	agentDone := make(chan error, 1)

	go func() {
		_, err := io.Copy(sshPipe, agentData)
		if debugClient {
			log.Printf("Finished copying ssh data from agent: %s", err)
		}
		if err != nil {
			sshPipe.Close()
			agentDone <- fmt.Errorf("failed to read ssh data from agent: %s", err)
			return
		}

		serverOut.mu.Lock()
		defer serverOut.mu.Unlock()

		handoffByte, err := getHandoffNextTransportByte(control)

		if err != nil {
			agentDone <- err
			sshPipe.Close()
			return
		}

		syncBufferedTraffic(bufferedTraffic, bufferedOffset, handoffByte)
		n, err := bufferedTraffic.WriteTo(sshPipe)
		if err != nil {
			agentDone <- fmt.Errorf("failed to backfill traffic from server to client: %s", err)
			sshPipe.Close()
			return
		}
		if debugClient {
			log.Printf("Backfilled %d bytes from server to client", n)
		}

		agentDone <- nil

		if serverOut.werr != nil {
			io.Copy(sshPipe, serverReader)
			sshPipe.Close()
		} else {
			agentTransport.Close()
			serverOut.w = sshPipe
		}

	}()

	go func() {
		_, err := io.Copy(&serverOut, serverReader)
		if debugClient {
			log.Printf("Finished copying transport data to agent")
		}
		serverOut.Close()
		if err != nil && err != os.ErrClosed && err != yamux.ErrStreamClosed {
			log.Printf("To agent transport forwarding failed: %s", err)
		}
	}()
	fromAgentTransportDone := make(chan error)
	go func() {
		_, err := io.Copy(serverWriter, &agentTransport)
		if debugClient {
			log.Printf("Finished copying transport data from agent")
		}
		if err != nil {
			fromAgentTransportDone <- fmt.Errorf("failed to copy data from agent to server: %s", err)
		} else {
			fromAgentTransportDone <- nil
		}
	}()

	doHandoffOnKex := make(chan chan error, 1)
	kexCallback := func() {
		if debugClient {
			log.Printf("KexCallback called")
		}
		var done chan error
		select {
		case done = <-doHandoffOnKex:
			break
		default:
			return
		}

		if debugClient {
			log.Printf("Starting transport rewiring")
		}

		if err = <-fromAgentTransportDone; err != nil {
			done <- fmt.Errorf("failed to forward agent transport data: %s", err)
			return
		}

		sshOut.mu.Lock()
		sshOut.w = serverWriter
		sshOut.mu.Unlock()

		go func() {
			done <- <-agentDone
		}()
	}

	config := ssh.ClientConfig{
		Config: ssh.Config{
			KexCallback: kexCallback,
		},
		HostKeyCallback:          ssh.InsecureIgnoreHostKey(),
		DeferHostKeyVerification: true,
	}

	c, chans, reqs, err := ssh.NewClientConn(sshClientConn, dc.HostPort, &config)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %s", dc.HostPort, err)
	}

	sshClient := ssh.NewClient(c, chans, reqs)
	if sshClient == nil {
		return fmt.Errorf("failed to connect to [%s]: %v", dc.HostPort, err)
	}

	defer sshClient.Close()

	if err = dc.startCommand(sshClient, dc.Cmd); err != nil {
		return fmt.Errorf("failed to run command: %s", err)
	}

	ok, _, err := sshClient.SendRequest(ssh.NoMoreSessionRequestName, true, nil)
	if err != nil {
		return fmt.Errorf("failed to send %s: %s", ssh.NoMoreSessionRequestName, err)
	}
	if !ok {
		log.Printf("%s request denied, continuing", ssh.NoMoreSessionRequestName)
	}

	handoffComplete := make(chan error, 1)
	doHandoffOnKex <- handoffComplete

	if debugClient {
		log.Printf("Initiating Handoff Key Exchange")
	}

	// First start buffering traffic from the server, since packets
	// sent by ther server after msgNewKeys might need to replayed
	// to the client after the handoff.
	serverOut.mu.Lock()
	serverOut.w = io.MultiWriter(bufferedTraffic, serverOut.w)
	bufferedOffset = agentTransport.BytesWritten()
	serverOut.mu.Unlock()

	sshClient.RequestKeyChange()
	errChan := make(chan error)
	go func() {
		errChan <- sshClient.Wait()
	}()

	select {
	case err = <-handoffComplete:
		if err != nil {
			return err
		}
		if debugClient {
			log.Printf("Handoff Complete")
		}
	case err = <-errChan:
		if debugClient {
			log.Printf("Command finished before handoff: %s", err)
		}
		if err != nil {
			return err
		}
	}

	return dc.resume()
}
