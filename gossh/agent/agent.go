package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"

	"github.com/dimakogan/ssh/gossh/common"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func proxySSH(toClient net.Conn, toServer net.Conn, control net.Conn) {
	var auths []ssh.AuthMethod
	if aconn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(aconn).Signers))
	}

	log.Printf("Connected to SSH_AUTH_SOCK")

	curuser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %s", err)
	}


	clientConfig := &ssh.ClientConfig{
		User:            curuser.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            auths,
	}

	meteredConnToServer := common.MeteredConn{Conn: toServer}
	proxy, err := ssh.NewProxyConn(toClient, &meteredConnToServer, clientConfig)
	if err != nil {
		fmt.Print(err)
		return
	}
	err = proxy.UpdateClientSessionParams()
	if err != nil {
		fmt.Print(err)
		return
	}

	done := proxy.Run()
	err = <-done
	if err != nil {
		log.Fatalf("Got error from proxy: %s", err)
	}

	handshakeCompletedMsg := common.HandoffCompleteMessage{
		MsgNum:            common.MsgHandoffComplete,
		NextTransportByte: uint32(meteredConnToServer.BytesRead() - proxy.BufferedFromServer()),
	}
	packet := ssh.Marshal(handshakeCompletedMsg)
	common.WriteControlPacket(control, packet)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	var cport int
	flag.IntVar(&cport, "c", 2345, "Control port to listen on.")

	var dport int
	flag.IntVar(&dport, "d", 3434, "SSH data port to listen to.")

	var tport int
	flag.IntVar(&tport, "t", 6789, "Transport port to connect to.")

	var pxAddr string
	flag.StringVar(&pxAddr, "px", "127.0.0.1", "Address for the ssh proxy.")


	curuser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %s", err)
	}
	var knownHosts string
	flag.StringVar(&knownHosts, "known_hosts", filepath.Join(curuser.HomeDir, ".ssh/known_hosts"), "known hosts to verify against")

	flag.Parse()

	controlListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", pxAddr, cport))
	if err != nil {
		log.Fatalf("Failed to listen on control port %d: %s", cport, err)
	}
	defer controlListener.Close()

	dataListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", pxAddr, dport))
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

		transport, err := net.Dial("tcp", fmt.Sprintf("%s:%d", pxAddr, tport))
		if err != nil {
			log.Printf("Failed to connect to local port %d: %s", tport, err)
		}
		defer transport.Close()
		log.Print("Connected to transport forwarding")

		proxySSH(sshData, transport, control)
		log.Print("Finished Proxy session")
		control.Close()
		sshData.Close()
		transport.Close()
	}
}
