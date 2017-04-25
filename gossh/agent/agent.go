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
)

func proxySsh(toClient net.Conn, toServer net.Conn, control net.Conn) {
	var auths []ssh.AuthMethod
	if aconn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(aconn).Signers))
	}

	log.Printf("Conected to SSH_AUTH_SOCK")

	curuser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %s", err)
	}

	clientConfig := &ssh.ClientConfig{
		User:            curuser.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            auths,
	}

	proxy, err := ssh.NewProxyConn(toClient, toServer, clientConfig)
	if err != nil {
		fmt.Print(err)
		return
	}

	var done <-chan error = proxy.Run()
	err = <-done
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	var cport int
	flag.IntVar(&cport, "c", 2345, "Control port to listen on.")

	var dport int
	flag.IntVar(&dport, "d", 3434, "SSH data port to listen to.")

	var tport int
	flag.IntVar(&tport, "t", 6789, "Transport port to connect to.")

	curuser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %s", err)
	}
	var known_hosts string
	flag.StringVar(&known_hosts, "known_hosts", filepath.Join(curuser.HomeDir, ".ssh/known_hosts"), "known hosts to verify against")

	flag.Parse()

	controlListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cport))
	if err != nil {
		log.Fatalf("Failed to listen on control port %d: %s", cport, err)
	}
	defer controlListener.Close()

	dataListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", dport))
	if err != nil {
		log.Fatalf("Failed to listen on data port %d: %s", dport, err)
	}
	defer dataListener.Close()

	for {
		control, err := controlListener.Accept()
		if err != nil {
			log.Printf("Failed to accept control connection: %s", err)
		}
		defer control.Close()
		log.Print("New incoming control connection")

		sshData, err := dataListener.Accept()
		if err != nil {
			log.Printf("Failed to accept data connection: %s", err)
		}
		defer sshData.Close()
		log.Print("New incoming data connection")

		transport, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tport))
		if err != nil {
			log.Printf("Failed to connect to local port %d: %s", tport, err)
		}
		defer transport.Close()
		log.Print("Connected to transport forwarding")

		proxySsh(sshData, transport, control)
	}
}
