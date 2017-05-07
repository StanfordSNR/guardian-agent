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
	"strings"
	"sync"
	"time"

	"github.com/dimakogan/ssh/gossh/common"
	"golang.org/x/crypto/ssh"
)

type commandExecution struct {
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	stderr  io.Reader
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
	go io.Copy(cmdExec.stdin, os.Stdin)
	go io.Copy(os.Stdout, cmdExec.stdout)
	go io.Copy(os.Stderr, cmdExec.stderr)
	return cmdExec.session.Wait()
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

	var port int
	flag.IntVar(&port, "p", 22, "Port to connect to on the remote host.")
	var cport int
	flag.IntVar(&cport, "c", 2345, "Proxy control port to connect to.")
	var dport int
	flag.IntVar(&dport, "d", 3434, "Data port to connect to.")
	var tport int
	flag.IntVar(&tport, "t", 6789, "Transport port to listen to.")
	var pxAddr string
	flag.StringVar(&pxAddr, "px", "127.0.0.1", "Address for the ssh proxy.")

	flag.Parse()
	if flag.NArg() < 1 {
		log.Fatalf("Usage: %s hostname", os.Args[0])
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
		cmd = flag.Args()[1]
	}

	log.Printf("Host: %s, Port: %d, User: %s\n", host, port, username)

	addr := fmt.Sprintf("%s:%d", host, port)
	serverConn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("Failed to connect to %s:%d: %s", host, port, err)
	}
	defer serverConn.Close()

	transportListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", pxAddr, tport))
	if err != nil {
		log.Fatalf("Failed to Listen on port %d: %s", tport, err)
	}
	defer transportListener.Close()

	control, err := net.Dial("tcp", fmt.Sprintf("%s:%d", pxAddr, cport))
	if err != nil {
		log.Printf("Failed to connect to proxy port %d: %s", cport, err)
	}
	defer control.Close()

	proxyData, err := net.Dial("tcp", fmt.Sprintf("%s:%d", pxAddr, dport))
	if err != nil {
		log.Printf("Failed to connect to proxy data port %d: %s", dport, err)
	}
	defer proxyData.Close()

	execReq := common.ExecutionRequestMessage{MsgNum: common.MsgExecutionRequest, User: username, Command: cmd, Server: host}

	execReqPacket := ssh.Marshal(execReq)
	common.WriteControlPacket(control, execReqPacket)
	log.Printf("MsgExecutionRequest sent to proxy\n")

	pt, err := transportListener.Accept()
	if err != nil {
		log.Printf("Failed to Accept connection: %s", err)
	}
	proxyTransport := common.MeteredConn{Conn: pt}
	defer proxyTransport.Close()
	log.Print("Got connection back from proxy\n")

	log.Printf("Starting delegated client...")

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
		log.Printf("Finsihed copying ssh data from proxy: %s", err)
		proxyDone <- err
	}()

	go io.Copy(&serverOut, serverConn)
	proxyTransportDone := make(chan error)
	go func() {
		_, err := io.Copy(serverConn, &proxyTransport)
		log.Printf("Finsihed copying transport data from proxy")
		proxyTransportDone <- err
	}()

	doHandoffOnKex := make(chan chan error, 1)
	// To be used to buffer traffic that needs to be replayed to the client
	// after the handoff (since the transport layer might deliver to the proxy
	// packets that the server has sent after msgNewKeys).
	bufferedTraffic := new(bytes.Buffer)
	kexCallback := func(err error) {
		log.Printf("KexCallback called")
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

		log.Printf("Starting transport rewiring")

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

		handoffPacket, err := common.ReadControlPacket(control)
		if handoffPacket[0] != common.MsgHandoffComplete {
			done <- fmt.Errorf("Unexpected msg: %d, when expecting MsgHandshakeCompleted", handoffPacket[0])
			return
		}
		handoffMsg := new(common.HandoffCompleteMessage)
		if err = ssh.Unmarshal(handoffPacket, handoffMsg); err != nil {
			done <- fmt.Errorf("Failed to unmarshal MsgHandshakeCompleted: %s", err)
			return
		}

		log.Printf("Got handoffMsg.NextTransportByte: %d", handoffMsg.NextTransportByte)

		time.Sleep(500 * time.Millisecond)
		serverOut.mu.Lock()
		serverOut.w = sshPipe

		backfillLen := int(uint32(proxyTransport.BytesWritten()) - handoffMsg.NextTransportByte)
		if backfillLen < 0 {
			done <- fmt.Errorf(
				"Unexpected negative backfill len, read from server: %d, reported by proxy: %d",
				proxyTransport.BytesWritten(), handoffMsg.NextTransportByte)
			serverOut.mu.Unlock()
			return
		}
		if backfillLen == 0 {
			log.Printf("No backfill necessary")
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
			log.Printf("Backfilled %d bytes from server to client", n)
			done <- nil
		}()
	}

	addr = "127.0.0.1:222"
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

	log.Printf("Creating NewClienConn")

	sshClient := ssh.NewClient(c, chans, reqs)
	if sshClient == nil {
		log.Printf("unable to connect to [%s]: %v", addr, err)
	}

	log.Printf("SSH Connected\n")
	defer sshClient.Close()

	session, err := startCommand(sshClient, cmd)
	if err != nil {
		log.Printf("Failed to run command: %s", err)
		return
	}

	// Uncomment this, together with running a long command (e.g., ping -c10 127.0.0.1),
	// to trigger a backfill condition.
	// time.Sleep(2 * time.Second)
	handoffComplete := make(chan error, 1)
	doHandoffOnKex <- handoffComplete

	log.Printf("Initiating Handoff Key Exchange")

	// First start buffering traffic from the server, since packets
	// sent by ther server after msgNewKeys might need to replayed
	// to the client after the handoff.
	serverOut.mu.Lock()
	serverOut.w = io.MultiWriter(serverOut.w, bufferedTraffic)
	serverOut.mu.Unlock()

	sshClient.RequestKeyChange()
	if err = <-handoffComplete; err != nil {
		log.Printf("Handoff failed: %s", err)
		return
	}
	log.Printf("Handoff Complete")

	err = session.resume()
	if err != nil {
		log.Printf("Command failed: %s", err)
	}
}
