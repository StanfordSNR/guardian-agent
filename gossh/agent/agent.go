package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os/user"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

func proxySsh(toClient net.Conn, toServer net.Conn) {
	proxy, err := ssh.NewProxyConn(toClient, toServer)
	if err != nil {
		fmt.Print(err)
		return
	}

	var done <-chan error = proxy.Run()
	err = <-done
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
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
		log.Print("New connection")
		outcon, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cport))
		if err != nil {
			log.Printf("Failed to connect to local port %d: %s", cport, err)
		}
		defer outcon.Close()
		proxySsh(incon, outcon)
	}
}
