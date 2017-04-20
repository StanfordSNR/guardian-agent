package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

func main() {
	var port int
	var known_hosts string

	curuser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %s", err)
	}

	flag.IntVar(&port, "p", 22, "Port to connect to on the remote host.")
	flag.StringVar(&known_hosts, "known_hosts", filepath.Join(curuser.HomeDir, ".ssh/known_hosts"), "known hosts to verify against")

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

	fmt.Printf("Host: %s, Port: %d, User: %s\n", host, port, username)

	var auths []ssh.AuthMethod
	if aconn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(aconn).Signers))

	}

	known_hosts_checker, err := knownhosts.New(known_hosts)
	if err != nil {
		log.Fatalf("Failed to read knownhosts file %s: %s", known_hosts, err)
	}

	config := ssh.ClientConfig{
		User:            username,
		Auth:            auths,
		HostKeyCallback: known_hosts_checker,
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := ssh.Dial("tcp", addr, &config)
	if err != nil {
		log.Fatalf("unable to connect to [%s]: %v", addr, err)
	}
	defer conn.Close()

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
