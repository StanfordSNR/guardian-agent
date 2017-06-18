package client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"sync"
	"time"

	"github.com/dimakogan/ssh/gossh/common"
	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/ssh"
)

const debugClient = false

type DelegatedClient struct {
	HostPort string
	Username string
	Cmd      string

	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	stderr  io.Reader
}

func findGuardSocket() (string, error) {
	locations := []string{os.Getenv("SSH_AUTH_SOCK"), path.Join(common.UserRuntimeDir(), common.AgentGuardSockName)}
	for _, loc := range locations {
		sock, err := net.Dial("unix", loc)
		if err != nil {
			continue
		}
		defer sock.Close()
		query := common.AgentCExtensionMsg{
			ExtensionType: common.AgentGuardExtensionType,
		}

		err = common.WriteControlPacket(sock, common.MsgAgentCExtension, ssh.Marshal(query))
		if err != nil {
			continue
		}

		msgNum, _, err := common.ReadControlPacket(sock)
		if err == nil && msgNum == common.MsgAgentSuccess {
			sock.Close()
			return loc, nil
		}
	}
	return "", os.ErrNotExist
}

type settableWriter struct {
	w  io.Writer
	mu sync.Mutex
}

func (sw *settableWriter) Write(p []byte) (n int, err error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	if sw.w == nil {
		return 0, errors.New("Writer is closed")
	}

	return sw.w.Write(p)
}

func (dc *DelegatedClient) startCommand(conn *ssh.Client, cmd string) (err error) {
	// TODO(dimakogan): initial window size should be set to probably 0, to avoid large amounts
	// of data to be transfered through proxy prior to handoff.
	dc.session, err = conn.NewSession()
	if err != nil {
		return fmt.Errorf("Failed to create session: %s", err)
	}

	dc.stdin, err = dc.session.StdinPipe()
	if err != nil {
		dc.session.Close()
		return err
	}
	dc.stdout, err = dc.session.StdoutPipe()
	if err != nil {
		dc.session.Close()
		return err
	}

	dc.stderr, err = dc.session.StderrPipe()
	if err != nil {
		dc.session.Close()
		return err
	}

	if err = dc.session.Start(cmd); err != nil {
		dc.session.Close()
		return err
	}

	return nil
}

func (dc *DelegatedClient) resume() error {
	defer dc.session.Close()
	go func() {
		io.Copy(dc.stdin, os.Stdin)
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

// Connect starts a delegated session.
func (dc *DelegatedClient) Run() error {
	serverConn, err := net.Dial("tcp", dc.HostPort)
	if err != nil {
		return fmt.Errorf("Failed to connect to %s: %s", dc.HostPort, err)
	}
	defer serverConn.Close()

	guardSock, err := findGuardSocket()
	if err != nil {
		return fmt.Errorf("Failed to find ssh auth socket: %s", err)
	}
	master, err := net.Dial("unix", guardSock)
	if err != nil {
		return fmt.Errorf("Failed to connect to proxy: %s", err)
	}
	defer master.Close()

	execReq := common.ExecutionRequestMessage{
		User:    dc.Username,
		Command: dc.Cmd,
		Server:  dc.HostPort,
	}

	execReqPacket := ssh.Marshal(execReq)
	err = common.WriteControlPacket(master, common.MsgExecutionRequest, execReqPacket)
	if err != nil {
		return fmt.Errorf("Failed to send MsgExecutionRequest to proxy: %s", err)
	}

	// Wait for response before opening data connection
	msgNum, msg, err := common.ReadControlPacket(master)
	if err != nil {
		return fmt.Errorf("Failed to get approval from agent: %s", err)
	}
	switch msgNum {
	case common.MsgExecutionApproved:
		break
	case common.MsgExecutionDenied:
		var denyMsg common.ExecutionDeniedMessage
		ssh.Unmarshal(msg, &denyMsg)
		return fmt.Errorf("Execution denied by agent: %s", denyMsg.Reason)
	default:
		return fmt.Errorf("Failed to get approval from agent, unknown reply: %d", msgNum)
	}

	ymux, err := yamux.Client(master, nil)
	defer ymux.Close()
	control, err := ymux.Open()
	if err != nil {
		return fmt.Errorf("Failed to get control stream: %s", err)
	}
	defer control.Close()
	// Proceed with approval
	proxyData, err := ymux.Open()
	if err != nil {
		return fmt.Errorf("Failed to get data stream: %s", err)
	}
	defer proxyData.Close()

	pt, err := ymux.Open()
	if err != nil {
		return fmt.Errorf("Failed to get transport stream: %s", err)
	}
	proxyTransport := common.CustomConn{Conn: pt}
	defer proxyTransport.Close()

	sshClientConn, sshPipe := net.Pipe()

	// Initially, the SSH connection is wired to the proxy data,
	// and the server connection is wired to the proxy transport.
	sshOut := settableWriter{w: proxyData}
	proxyOut := settableWriter{w: sshPipe}
	serverOut := settableWriter{w: &proxyTransport}

	go io.Copy(&sshOut, sshPipe)
	proxyDone := make(chan error)
	go func() {
		_, err := io.Copy(&proxyOut, proxyData)
		if debugClient {
			log.Printf("Finished copying ssh data from proxy: %s", err)
		}
		proxyDone <- err
	}()

	go io.Copy(&serverOut, serverConn)
	proxyTransportDone := make(chan error)
	go func() {
		_, err := io.Copy(serverConn, &proxyTransport)
		if debugClient {
			log.Printf("Finished copying transport data from proxy")
		}
		proxyTransportDone <- err
	}()

	doHandoffOnKex := make(chan chan error, 1)
	// To be used to buffer traffic that needs to be replayed to the client
	// after the handoff (since the transport layer might deliver to the proxy
	// packets that the server has sent after msgNewKeys).
	bufferedTraffic := new(bytes.Buffer)
	kexCallback := func(err error) {
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

		if err != nil {
			done <- err
			return
		}

		if debugClient {
			log.Printf("Starting transport rewiring")
		}

		if err = <-proxyTransportDone; err != nil {
			done <- fmt.Errorf("Proxy transport forwarding failed: %s", err)
			return
		}
		sshOut.mu.Lock()
		sshOut.w = serverConn
		sshOut.mu.Unlock()

		if err = <-proxyDone; err != nil {
			done <- fmt.Errorf("Proxy ssh data forwarding failed: %s", err)
			return
		}

		msgNum, handoffPacket, err := common.ReadControlPacket(control)
		if msgNum != common.MsgHandoffComplete {
			done <- fmt.Errorf("Unexpected msg: %d, when expecting MsgHandshakeCompleted", handoffPacket[0])
			return
		}
		handoffMsg := new(common.HandoffCompleteMessage)
		if err = ssh.Unmarshal(handoffPacket, handoffMsg); err != nil {
			done <- fmt.Errorf("Failed to unmarshal MsgHandshakeCompleted: %s", err)
			return
		}

		if debugClient {
			log.Printf("Got handoffMsg.NextTransportByte: %d", handoffMsg.NextTransportByte)
		}

		time.Sleep(500 * time.Millisecond)
		serverOut.mu.Lock()
		serverOut.w = sshPipe

		// Close the connection to the proxy
		master.Close()

		backfillLen := int(uint32(proxyTransport.BytesWritten()) - handoffMsg.NextTransportByte)
		if backfillLen < 0 {
			done <- fmt.Errorf(
				"Unexpected negative backfill len, read from server: %d, reported by proxy: %d",
				proxyTransport.BytesWritten(), handoffMsg.NextTransportByte)
			serverOut.mu.Unlock()
			return
		}
		if backfillLen == 0 {
			if debugClient {
				log.Printf("No backfill necessary")
			}
			done <- nil
			serverOut.mu.Unlock()
			return
		}
		if bufferedTraffic.Len() < backfillLen {
			done <- fmt.Errorf("Missing bytes to backfill, required: %d, available: %d", backfillLen, bufferedTraffic.Len())
			serverOut.mu.Unlock()
			return
		}
		bufferedTraffic.Next(bufferedTraffic.Len() - backfillLen)

		//sshServerConn is unbuffered so we empty the buffer in a separate goroutine to avoid a deadlock
		go func() {
			defer serverOut.mu.Unlock()
			n, err := bufferedTraffic.WriteTo(sshPipe)
			if err != nil {
				done <- fmt.Errorf("Failed to backfill traffic from server to client: %s", err)
			}
			if debugClient {
				log.Printf("Backfilled %d bytes from server to client", n)
			}
			done <- nil
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
		return fmt.Errorf("Failed to create NewClientConn:%s", err)
	}

	sshClient := ssh.NewClient(c, chans, reqs)
	if sshClient == nil {
		return fmt.Errorf("Failed to connect to [%s]: %v", dc.HostPort, err)
	}

	defer sshClient.Close()

	if err = dc.startCommand(sshClient, dc.Cmd); err != nil {
		return fmt.Errorf("Failed to run command: %s", err)
	}

	ok, _, err := sshClient.SendRequest(ssh.NoMoreSessionRequestName, true, nil)
	if err != nil {
		return fmt.Errorf("Failed to send %s: %s", ssh.NoMoreSessionRequestName, err)
	}
	if !ok {
		log.Printf("%s request denied, continuing", ssh.NoMoreSessionRequestName)
	}

	// Uncomment this, together with running a long command (e.g., ping -c10 127.0.0.1),
	// to trigger a backfill condition.
	time.Sleep(2 * time.Second)
	handoffComplete := make(chan error, 1)
	doHandoffOnKex <- handoffComplete

	if debugClient {
		log.Printf("Initiating Handoff Key Exchange")
	}

	// First start buffering traffic from the server, since packets
	// sent by ther server after msgNewKeys might need to replayed
	// to the client after the handoff.
	serverOut.mu.Lock()
	serverOut.w = io.MultiWriter(serverOut.w, bufferedTraffic)
	serverOut.mu.Unlock()

	sshClient.RequestKeyChange()
	errChan := make(chan error)
	go func() {
		errChan <- sshClient.Wait()
	}()

	select {
	case err = <-handoffComplete:
		if err != nil {
			return fmt.Errorf("Handoff failed: %s", err)
		}
		if debugClient {
			log.Printf("Handoff Complete")
		}
	case err = <-errChan:
		if debugClient {
			log.Printf("Command finished before handoff: %s", err)
		}
		if err != nil {
			log.Printf("Connection error: %s", err)
		}
	}

	return dc.resume()
}
