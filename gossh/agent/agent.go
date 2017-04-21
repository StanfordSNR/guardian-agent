package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

func forwardSsh(incon net.Conn, outcon net.Conn, known_hosts string) {
	log.Printf("Forwarding SSH begin...")

	var auths []ssh.AuthMethod
	if aconn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(aconn).Signers))
	}

	log.Printf("Conected to SSH_AUTH_SOCK")

	known_hosts_checker, err := knownhosts.New(known_hosts)
	if err != nil {
		log.Fatalf("Failed to read knownhosts file %s: %s", known_hosts, err)
	}

	curuser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %s", err)
	}

	addr := "127.0.0.1:222"
	config := ssh.ClientConfig{
		User:            curuser.Username,
		Auth:            auths,
		HostKeyCallback: known_hosts_checker,
	}

	c, chans, reqs, err := ssh.NewClientConn(outcon, addr, &config)
	if err != nil {
		log.Printf("Failed to create NewClientConn:%s", err)
		return
	}

	log.Printf("Create NewClienConn")

	ssh_client := ssh.NewClient(c, chans, reqs)
	if ssh_client == nil {
		log.Printf("unable to connect to [%s]: %v", addr, err)
	}

	log.Printf("SSH Connected\n")
	defer ssh_client.Close()
}

func main() {
	var lport int
	flag.IntVar(&lport, "l", 2345, "Port to listen on.")

	var cport int
	flag.IntVar(&cport, "c", 6789, "Port to connect to.")

	curuser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %s", err)
	}
	var known_hosts string
	flag.StringVar(&known_hosts, "known_hosts", filepath.Join(curuser.HomeDir, ".ssh/known_hosts"), "known hosts to verify against")

	flag.Parse()

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", lport))
	if err != nil {
		log.Fatalf("Failed to List on port %d: %s", lport, err)
	}
	defer ln.Close()

	for {
		incon, err := ln.Accept()
		if err != nil {
			log.Printf("Failed to Accept connection: %s", err)
		}
		defer incon.Close()
		fmt.Print("New connection")
		outcon, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cport))
		if err != nil {
			log.Printf("Failed to connect to local port %d: %s", cport, err)
		}
		defer outcon.Close()
		forwardSsh(incon, outcon, known_hosts)
	}
}
