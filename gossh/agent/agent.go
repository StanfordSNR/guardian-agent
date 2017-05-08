package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"

	"path"

	"github.com/dimakogan/ssh/gossh/common"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

func proxySSH(toClient net.Conn, toServer net.Conn, control net.Conn, pc *ssh.Policy) error {
	var auths []ssh.AuthMethod
	aconn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return err
	}

	auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(aconn).Signers))

	if err != nil {
		return err
	}

	curuser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %s", err)
	}
	kh, err := knownhosts.New(path.Join(curuser.HomeDir, ".ssh", "known_hosts"))
	if err != nil {
		return err
	}
	clientConfig := &ssh.ClientConfig{
		User:            pc.User,
		HostKeyCallback: kh,
		Auth:            auths,
	}

	meteredConnToServer := common.CustomConn{Conn: toServer}
	proxy, err := ssh.NewProxyConn(pc.Server, toClient, &meteredConnToServer, clientConfig, pc.FilterPacket)
	if err != nil {
		return err
	}
	err = proxy.UpdateClientSessionParams()
	if err != nil {
		return err
	}

	done := proxy.Run()
	err = <-done
	if err != nil {
		return err
	}

	handshakeCompletedMsg := common.HandoffCompleteMessage{
		MsgNum:            common.MsgHandoffComplete,
		NextTransportByte: uint32(meteredConnToServer.BytesRead() - proxy.BufferedFromServer()),
	}
	packet := ssh.Marshal(handshakeCompletedMsg)
	return common.WriteControlPacket(control, packet)
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

		controlPacket, err := common.ReadControlPacket(control)
		if controlPacket[0] != common.MsgExecutionRequest {
			log.Printf("Unexpected control message: %d (expecting MsgExecutionRequest)", controlPacket[0])
			continue
		}
		execReq := new(common.ExecutionRequestMessage)
		if err = ssh.Unmarshal(controlPacket, execReq); err != nil {
			log.Print("Failed to unmarshal ExecutionRequestMessage: %s", err)
			continue
		}

		policyControl := ssh.NewPolicy(execReq.User, execReq.Command, execReq.Server)

		err = policyControl.AskForApproval()
		if err != nil {
			log.Printf("Policy error: %s", err)
			// TODO(sternh): this shouldn't exit, but rather reply to client and proceed to next req
			// send disconnect on ssh data channel, and a deny on control channel
			// or defer?/handle incoming connection
			continue
		}

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

		err = proxySSH(sshData, transport, control, policyControl)
		log.Printf("Finished Proxy session: %s", err)
		control.Close()
		sshData.Close()
		transport.Close()
	}
}
