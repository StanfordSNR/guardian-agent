package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"strings"

	"golang.org/x/crypto/ssh"
)

func resume_ssh(conn *ssh.Client) {
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

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	curuser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %s", err)
	}

	var port int
	flag.IntVar(&port, "p", 22, "Port to connect to on the remote host.")
	var cport int
	flag.IntVar(&cport, "c", 2345, "Port to connect to proxy.")
	var lport int
	flag.IntVar(&lport, "l", 6789, "Port to listen for tcp forwarding.")

	flag.Parse()
	if flag.NArg() < 1 {
		log.Fatalf("Usage: %s hostname", os.Args[0])
	}

	user_host := strings.Split(flag.Args()[0], "@")
	var username string
	var host string
	if len(user_host) > 1 {
		username, host = user_host[0], user_host[1]
	} else {
		username = curuser.Username
		host = user_host[0]
	}

	log.Printf("Host: %s, Port: %d, User: %s\n", host, port, username)

	addr := fmt.Sprintf("%s:%d", host, port)
	rcon, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("Failed to connect to %s:%d: %s", host, port, err)
	}
	defer rcon.Close()

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", lport))
	if err != nil {
		log.Fatalf("Failed to Listen on port %d: %s", lport, err)
	}
	defer ln.Close()

	outcon, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cport))
	if err != nil {
		log.Printf("Failed to connect to proxy port %d: %s", cport, err)
	}
	defer outcon.Close()

	incon, err := ln.Accept()
	if err != nil {
		log.Printf("Failed to Accept connection: %s", err)
	}
	defer incon.Close()
	log.Print("Got connection back from proxy\n")
	go io.Copy(incon, rcon)
	go io.Copy(rcon, incon)

	log.Printf("Starting delegated client...")

	addr = "127.0.0.1:222"
	config := ssh.ClientConfig{
		HostKeyCallback:          ssh.InsecureIgnoreHostKey(),
		DeferHostKeyVerification: true,
	}

	c, chans, reqs, err := ssh.NewClientConn(outcon, addr, &config)
	if err != nil {
		log.Printf("Failed to create NewClientConn:%s", err)
		return
	}

	log.Printf("Creating NewClienConn")

	ssh_client := ssh.NewClient(c, chans, reqs)
	if ssh_client == nil {
		log.Printf("unable to connect to [%s]: %v", addr, err)
	}

	log.Printf("SSH Connected\n")
	defer ssh_client.Close()

	tmp := make([]byte, 256)
	outcon.Read(tmp)
}
