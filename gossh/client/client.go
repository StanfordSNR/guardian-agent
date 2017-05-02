package main

import (
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

	"golang.org/x/crypto/ssh"
)

func resumeSSH(conn *ssh.Client) {
	session, err := conn.NewSession()
	if err != nil {
		log.Fatalf("Failed to create session: %s", err)
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		log.Fatalf("Unable to setup stdin for session: %v", err)
	}
	go io.Copy(stdin, os.Stdin)

	stdout, err := session.StdoutPipe()
	if err != nil {
		log.Fatalf("Unable to setup stdout for session: %v", err)
	}
	go io.Copy(os.Stdout, stdout)

	stderr, err := session.StderrPipe()
	if err != nil {
		log.Fatalf("Unable to setup stderr for session: %v", err)
	}
	go io.Copy(os.Stderr, stderr)

	var cmd string
	if flag.NArg() < 2 {
		cmd = "ls -la"
	} else {
		cmd = flag.Args()[1]
	}

	err = session.Run(cmd)
	if err != nil {
		log.Fatalf("Failed to run command: %s", err)
	}

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

	log.Printf("Host: %s, Port: %d, User: %s\n", host, port, username)

	addr := fmt.Sprintf("%s:%d", host, port)
	serverConn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("Failed to connect to %s:%d: %s", host, port, err)
	}
	defer serverConn.Close()

	transportListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tport))
	if err != nil {
		log.Fatalf("Failed to Listen on port %d: %s", tport, err)
	}
	defer transportListener.Close()

	control, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cport))
	if err != nil {
		log.Printf("Failed to connect to proxy port %d: %s", cport, err)
	}
	defer control.Close()

	proxyData, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", dport))
	if err != nil {
		log.Printf("Failed to connect to proxy data port %d: %s", dport, err)
	}
	defer proxyData.Close()

	proxyTransport, err := transportListener.Accept()
	if err != nil {
		log.Printf("Failed to Accept connection: %s", err)
	}
	defer proxyTransport.Close()
	log.Print("Got connection back from proxy\n")

	log.Printf("Starting delegated client...")

	sshClientConn, sshServerConn := net.Pipe()

	// Initially, the SSH connection is wired to the proxy data,
	// and the server connection is wired to the proxy transport.
	sshOut := settableWriter{w: proxyData}
	proxyOut := settableWriter{w: sshServerConn}
	serverOut := settableWriter{w: proxyTransport}

	go io.Copy(&sshOut, sshServerConn)
	proxyDone := make(chan error)
	go func() {
		_, err := io.Copy(&proxyOut, proxyData)
		log.Printf("Finsihed copying ssh data from proxy: %s", err)
		proxyDone <- err
	}()

	go io.Copy(&serverOut, serverConn)
	proxyTransportDone := make(chan error)
	go func() {
		_, err := io.Copy(serverConn, proxyTransport)
		log.Printf("Finsihed copying transport data from proxy")
		proxyTransportDone <- err
	}()

	doHandoffOnKex := make(chan chan error, 1)
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

		serverOut.mu.Lock()
		serverOut.w = sshServerConn
		serverOut.mu.Unlock()

		done <- nil
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

	handoffComplete := make(chan error, 1)
	doHandoffOnKex <- handoffComplete

	log.Printf("Initiating Handoff Key Exchange")
	sshClient.RequestKeyChange()

	if err = <-handoffComplete; err != nil {
		log.Printf("Handoff failed: %s", err)
		return
	}
	log.Printf("Handoff Complete")

	resumeSSH(sshClient)
	tmp := make([]byte, 256)
	control.Read(tmp)
}
