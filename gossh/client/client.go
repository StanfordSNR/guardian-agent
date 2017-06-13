package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/dimakogan/ssh/gossh/common"
	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/ssh"
)

const debugClient = false

type commandExecution struct {
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	stderr  io.Reader
}

func SockFullPath() (string, error) {
	sockPath := os.Getenv("SSH_AUTH_SOCK")
	if sockPath != "" {
		if _, err := os.Stat(sockPath); err == nil {
			return sockPath, nil
		}
	}
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir != "" {
		sockPath = path.Join(dir, common.AgentGuardSockName)
		if _, err := os.Stat(sockPath); err == nil {
			return sockPath, nil
		}
	}
	curuser, err := user.Current()
	if err != nil {
		return "", err
	}
	sockPath = path.Join(curuser.HomeDir, ".ssh", common.AgentGuardSockName)
	if _, err := os.Stat(sockPath); err == nil {
		return sockPath, nil
	}
	return "", os.ErrNotExist
}

func startCommand(conn *ssh.Client, cmd string) (cmdExec *commandExecution, err error) {
	cmdExec = &commandExecution{}
	// TODO(dimakogan): initial window size should be set to probably 0, to avoid large amounts
	// of data to be transfered through proxy prior to handoff.
	cmdExec.session, err = conn.NewSession()
	if err != nil {
		log.Fatalf("Failed to create session: %s", err)
	}

	cmdExec.stdin, err = cmdExec.session.StdinPipe()
	if err != nil {
		cmdExec.session.Close()
		return nil, err
	}
	cmdExec.stdout, err = cmdExec.session.StdoutPipe()
	if err != nil {
		cmdExec.session.Close()
		return nil, err
	}

	cmdExec.stderr, err = cmdExec.session.StderrPipe()
	if err != nil {
		cmdExec.session.Close()
		return nil, err
	}

	if err = cmdExec.session.Start(cmd); err != nil {
		cmdExec.session.Close()
		return nil, err
	}

	return cmdExec, nil
}

func (cmdExec *commandExecution) resume() error {
	defer cmdExec.session.Close()
	go func() {
		io.Copy(cmdExec.stdin, os.Stdin)
		cmdExec.stdin.Close()
	}()
	done := make(chan error)
	go func() {
		_, err := io.Copy(os.Stdout, cmdExec.stdout)
		done <- err
	}()
	go func() {
		_, err := io.Copy(os.Stderr, cmdExec.stderr)
		done <- err
	}()

	errExec := cmdExec.session.Wait()
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

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	curuser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %s", err)
	}

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-p port] [user@]hostname [command]\n", os.Args[0])
		flag.PrintDefaults()
	}

	var port int
	flag.IntVar(&port, "p", 22, "Port to connect to on the remote host.")

	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	userHost := strings.Split(flag.Args()[0], "@")
	var username string
	var host string
	if len(userHost) > 1 {
		username, host = userHost[0], userHost[1]
	} else {
		username = curuser.Username
		host = userHost[0]
	}

	var cmd string
	if flag.NArg() < 2 {
		cmd = "ls -la"
	} else {
		cmd = strings.Join(flag.Args()[1:], " ")
	}

	if debugClient {
		log.Printf("Host: %s, Port: %d, User: %s\n", host, port, username)
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	serverConn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to connect to %s:%d: %s", host, port, err)
	}
	defer serverConn.Close()

	guardSock, err := SockFullPath()
	if err != nil {
		log.Fatalf("Failed to find ssh auth socket: %s", err)
	}
	master, err := net.Dial("unix", guardSock)
	if err != nil {
		log.Fatalf("Failed to connect to proxy: %s", err)
	}
	defer master.Close()

	execReq := common.ExecutionRequestMessage{
		User:    username,
		Command: cmd,
		Server:  fmt.Sprintf("%s:%d", host, port),
	}

	execReqPacket := ssh.Marshal(execReq)
	err = common.WriteControlPacket(master, common.MsgExecutionRequest, execReqPacket)
	if err != nil {
		log.Fatalf("Failed to send MsgExecutionRequest to proxy: %s", err)
	}

	// Wait for response before opening data connection
	msgNum, _, err := common.ReadControlPacket(master)
	if msgNum != common.MsgExecutionApproved {
		log.Fatalf("Execution was denied: %s", err)
	}

	ymux, err := yamux.Client(master, nil)
	defer ymux.Close()
	control, err := ymux.Open()
	if err != nil {
		log.Fatalf("Failed to get control stream: %s", err)
	}
	defer control.Close()
	// Proceed with approval
	proxyData, err := ymux.Open()
	if err != nil {
		log.Fatalf("Failed to get data stream: %s", err)
	}
	defer proxyData.Close()

	pt, err := ymux.Open()
	if err != nil {
		log.Fatalf("Failed to get transport stream: %s", err)
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

	c, chans, reqs, err := ssh.NewClientConn(sshClientConn, addr, &config)
	if err != nil {
		log.Printf("Failed to create NewClientConn:%s", err)
		return
	}

	sshClient := ssh.NewClient(c, chans, reqs)
	if sshClient == nil {
		log.Printf("Failed to connect to [%s]: %v", addr, err)
	}

	defer sshClient.Close()

	session, err := startCommand(sshClient, cmd)
	if err != nil {
		log.Printf("Failed to run command: %s", err)
		return
	}

	ok, _, err := sshClient.SendRequest(ssh.NoMoreSessionRequestName, true, nil)
	if err != nil {
		log.Printf("Failed to send %s: %s", ssh.NoMoreSessionRequestName, err)
		return
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
			log.Printf("Handoff failed: %s", err)
			return
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
	err = session.resume()
	if err != nil {
		log.Printf("Command failed: %s", err)
	}
}
