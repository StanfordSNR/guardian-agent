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
	"os/signal"
	"os/user"
	"path"
	"sync"

	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

const debugClient = true

type SSHCommand struct {
	HostPort     string
	Username     string
	Cmd          string
	ProxyCommand string
	StdinNull    bool
	ForceTty     bool
}

type client struct {
	SSHCommand

	agentConn        net.Conn
	sshClient        *ssh.Client
	session          *ssh.Session
	stdin            io.WriteCloser
	stdout           io.Reader
	stderr           io.Reader
	oldTerminalState *terminal.State
}

func (c *client) connectToAgent() error {
	locations := []string{path.Join(UserRuntimeDir(), AgentGuardSockName)}
	for _, loc := range locations {
		sock, err := net.Dial("unix", loc)
		if err != nil {
			continue
		}
		query := AgentCExtensionMsg{
			ExtensionType: AgentGuardExtensionType,
		}

		err = WriteControlPacket(sock, MsgAgentCExtension, ssh.Marshal(query))
		if err != nil {
			continue
		}

		msgNum, _, err := ReadControlPacket(sock)
		if err == nil && msgNum == MsgAgentSuccess {
			c.agentConn = sock
			return nil
		}
		sock.Close()
	}
	return fmt.Errorf("Failed to connect to agent guard. Did you setup agent guard forwarding to this host?")
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
	if cw, ok := sw.w.(CloseWriter); ok {
		return cw.CloseWrite()
	} else if c, ok := sw.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (c *client) Close() error {
	if c.oldTerminalState != nil {
		terminal.Restore(int(os.Stdin.Fd()), c.oldTerminalState)
	}
	if c.session != nil {
		c.session.Close()
	}
	if c.agentConn != nil {
		c.agentConn.Close()
	}
	if c.sshClient != nil {
		c.sshClient.Close()
	}
	return nil
}

func (c *client) startCommand(conn *ssh.Client, cmd string) (err error) {
	// TODO(dimakogan): initial window size should be set to probably 0, to avoid large amounts
	// of data to be transfered through agent prior to handoff.
	c.session, err = conn.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %s", err)
	}

	c.stdin, err = c.session.StdinPipe()
	if err != nil {
		c.session.Close()
		return fmt.Errorf("failed to setup stdin: %s", err)
	}
	c.stdout, err = c.session.StdoutPipe()
	if err != nil {
		c.session.Close()
		return fmt.Errorf("failed to setup stdout: %s", err)
	}

	c.stderr, err = c.session.StderrPipe()
	if err != nil {
		c.session.Close()
		return fmt.Errorf("failed to setup stderr: %s", err)
	}

	if cmd == "" || c.ForceTty {
		// Set up terminal modes -- use some reasonable defaults
		modes := ssh.TerminalModes{
			ssh.TTY_OP_ISPEED: 38400, // baud in
			ssh.TTY_OP_OSPEED: 38400, // baud out
			ssh.VINTR:         3,
			ssh.VQUIT:         28,
			ssh.VERASE:        127,
			ssh.VKILL:         21,
			ssh.VEOF:          4,
			ssh.VEOL:          0,
			ssh.VEOL2:         0,
			ssh.VSTART:        17,
			ssh.VSTOP:         19,
			ssh.VSUSP:         26,
			ssh.VREPRINT:      18,
			ssh.VWERASE:       23,
			ssh.VLNEXT:        22,
			ssh.VDISCARD:      15,
			ssh.PARMRK:        0,
			ssh.INPCK:         0,
			ssh.ISTRIP:        0,
			ssh.INLCR:         0,
			ssh.IGNCR:         0,
			ssh.IUCLC:         0,
			ssh.IXANY:         0,
			ssh.IXOFF:         0,
			ssh.IMAXBEL:       0,
			ssh.XCASE:         0,
			ssh.ECHO:          1,
			ssh.ECHOE:         1,
			ssh.ECHOK:         1,
			ssh.ECHOCTL:       1,
			ssh.ICRNL:         1,
			ssh.ONLCR:         1,
			ssh.IXON:          1,
			ssh.ISIG:          1,
			ssh.ICANON:        1,
			ssh.IEXTEN:        1,
			ssh.ECHOKE:        1,
			ssh.OPOST:         1,
			ssh.CS7:           1,
			ssh.CS8:           1,
			ssh.IGNPAR:        0,
			ssh.ECHONL:        0,
			ssh.NOFLSH:        0,
			ssh.TOSTOP:        0,
			ssh.PENDIN:        0,
			ssh.OLCUC:         0,
			ssh.OCRNL:         0,
			ssh.ONOCR:         0,
			ssh.ONLRET:        0,
			ssh.PARENB:        0,
			ssh.PARODD:        0,
		}
		w, h, err := terminal.GetSize(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("failed to get terminal size: %s", err)
		}
		if err := c.session.RequestPty(os.Getenv("TERM"), h, w, modes); err != nil {
			return fmt.Errorf("request for pseudo terminal failed: %s", err)
		}
		if terminal.IsTerminal(int(os.Stdin.Fd())) {
			oldState, err := terminal.MakeRaw(int(os.Stdin.Fd()))
			if err != nil {
				log.Printf("Failed to switch local terminal to raw mode: %s", err)
			} else {
				c.oldTerminalState = oldState
				sigch := make(chan os.Signal, 1)
				signal.Notify(sigch, os.Interrupt)
				go func() {
					for _ = range sigch {
						terminal.Restore(int(os.Stdin.Fd()), oldState)
						os.Exit(1)
					}
				}()
			}
		}
	}
	if cmd == "" {
		err = c.session.Shell()
	} else {
		err = c.session.Start(cmd)
	}
	if err != nil {
		c.session.Close()
		return err
	}

	return nil
}

func (c *client) resume() error {
	go func() {
		if !c.StdinNull {
			io.Copy(c.stdin, os.Stdin)
		}
		c.stdin.Close()
	}()
	done := make(chan error)
	go func() {
		_, err := io.Copy(os.Stdout, c.stdout)
		done <- err
	}()
	go func() {
		_, err := io.Copy(os.Stderr, c.stderr)
		done <- err
	}()

	errExec := c.session.Wait()
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

type CloseWriter interface {
	CloseWrite() error
}

func (c *client) connectToServer() (reader io.ReadCloser, writer io.WriteCloser, err error) {
	if c.ProxyCommand != "" {
		proxyChild := exec.Command(os.Getenv("SHELL"), "-c", "exec "+c.ProxyCommand)

		proxyChild.Stderr = os.Stderr
		reader, err = proxyChild.StdoutPipe()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get stdout pipe of ProxyCommand process: %s", err)
		}
		writer, err = proxyChild.StdinPipe()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get stdin pipe of ProxyCommand process: %s", err)
		}

		if err := proxyChild.Start(); err != nil {
			return nil, nil, fmt.Errorf("failed to run ProxyCommand %s: %s", c.ProxyCommand, err)
		}

		go func() {
			proxyChild.Wait()
		}()
		return reader, writer, nil
	} else {
		serverConn, err := net.Dial("tcp", c.HostPort)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to connect to %s: %s", c.HostPort, err)
		}
		return serverConn, serverConn, nil
	}
}

// Run starts a delegated session.
func RunSSHCommand(cmd SSHCommand) error {
	cli := client{SSHCommand: cmd}
	defer cli.Close()
	if cli.connectToAgent() == nil {
		return cli.runDelegated()
	}
	return cli.runDirect()
}

func (c *client) runDirect() error {
	serverReader, serverWriter, err := c.connectToServer()
	if err != nil {
		return err
	}
	serverEnd, clientEnd := net.Pipe()
	go func() {
		io.Copy(serverWriter, serverEnd)
		if cw, ok := serverWriter.(CloseWriter); ok {
			cw.CloseWrite()
		} else {
			serverWriter.Close()
		}
	}()

	go func() {
		io.Copy(serverEnd, serverReader)
		serverEnd.Close()
	}()

	curuser, err := user.Current()
	if err != nil {
		return fmt.Errorf("Failed to get current user: %s", err)
	}
	ui := FancyTerminalUI{}
	config := ssh.ClientConfig{
		User: c.Username,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return HostKeyCallback(hostname, remote, key, &ui)
		},
		Auth: getAuth(c.Username, c.HostPort, curuser.HomeDir, &ui),
	}

	cc, chans, reqs, err := ssh.NewClientConn(clientEnd, c.HostPort, &config)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %s", c.HostPort, err)
	}

	c.sshClient = ssh.NewClient(cc, chans, reqs)
	if c.sshClient == nil {
		return fmt.Errorf("failed to connect to %s: %v", c.HostPort, err)
	}

	if err = c.startCommand(c.sshClient, c.Cmd); err != nil {
		return fmt.Errorf("failed to run command: %s", err)
	}

	return c.resume()

}

func (c *client) runDelegated() error {
	serverReader, serverWriter, err := c.connectToServer()
	if err != nil {
		return err
	}

	execReq := ExecutionRequestMessage{
		User:    c.Username,
		Command: c.Cmd,
		Server:  c.HostPort,
	}

	execReqPacket := ssh.Marshal(execReq)
	err = WriteControlPacket(c.agentConn, MsgExecutionRequest, execReqPacket)
	if err != nil {
		return fmt.Errorf("failed to send MsgExecutionRequest to agent: %s", err)
	}

	// Wait for response before opening data connection
	msgNum, msg, err := ReadControlPacket(c.agentConn)
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

	ymux, err := yamux.Client(c.agentConn, nil)
	control, err := ymux.Open()
	if err != nil {
		return fmt.Errorf("failed to get control stream: %s", err)
	}
	// Proceed with approval
	agentData, err := ymux.Open()
	if err != nil {
		return fmt.Errorf("failed to get data stream: %s", err)
	}
	pt, err := ymux.Open()
	if err != nil {
		return fmt.Errorf("failed to get transport stream: %s", err)
	}
	agentTransport := CustomConn{Conn: pt}

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

	runningRoutines := sync.WaitGroup{}
	defer runningRoutines.Wait()

	runningRoutines.Add(1)
	go func() {
		defer runningRoutines.Done()

		_, err := io.Copy(&sshOut, sshPipe)
		if err != nil {
			log.Printf("Error copying outgoing SSH data: %s", err)
		} else {
			log.Printf("Finished copying outgoing SSH data")
		}
		sshOut.mu.Lock()
		sshOut.Close()
		sshOut.w = nil
		sshOut.mu.Unlock()
	}()

	agentDone := make(chan error, 1)
	runningRoutines.Add(1)
	go func() {
		defer runningRoutines.Done()
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

	runningRoutines.Add(1)
	go func() {
		defer runningRoutines.Done()
		_, err := io.Copy(&serverOut, serverReader)
		if debugClient {
			log.Printf("Finished copying transport data to agent")
		}
		serverOut.Close()
		if err != nil && err != os.ErrClosed && err != yamux.ErrStreamClosed {
			log.Printf("To agent transport forwarding failed: %s", err)
		}
	}()
	fromAgentTransportDone := make(chan error, 1)

	runningRoutines.Add(1)
	go func() {
		defer runningRoutines.Done()

		_, err := io.Copy(serverWriter, &agentTransport)
		if debugClient {
			log.Printf("Finished copying transport data from agent")
		}

		sshOut.mu.Lock()
		if sshOut.w != nil {
			sshOut.Close()
			sshOut.w = serverWriter
		} else {
			if cw, ok := serverWriter.(CloseWriter); ok {
				log.Printf("CloseWrite serverWriter")
				cw.CloseWrite()
			} else {
				log.Printf("Close serverWriter")
				serverWriter.Close()
			}
		}
		sshOut.mu.Unlock()

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

	cc, chans, reqs, err := ssh.NewClientConn(sshClientConn, c.HostPort, &config)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %s", c.HostPort, err)
	}

	c.sshClient = ssh.NewClient(cc, chans, reqs)
	if c.sshClient == nil {
		return fmt.Errorf("failed to connect to [%s]: %v", c.HostPort, err)
	}
	defer c.sshClient.Close()

	if err = c.startCommand(c.sshClient, c.Cmd); err != nil {
		return fmt.Errorf("failed to run command: %s", err)
	}

	ok, _, err := c.sshClient.SendRequest(ssh.NoMoreSessionRequestName, true, nil)
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

	c.sshClient.RequestKeyChange()
	errChan := make(chan error)
	go func() {
		errChan <- c.sshClient.Wait()
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
	return c.resume()
}
