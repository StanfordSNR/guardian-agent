package main

import (
	"bufio"
	"io"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path"
	"strings"

	"golang.org/x/crypto/ssh"

	"net"

	"strconv"

	"fmt"

	"io/ioutil"

	"github.com/dimakogan/ssh/gossh/common"
)

// RemoteStubName is the name of the stub executable on the remote machine.
const RemoteStubName = "~/sshfwdstub"

const debugSSHFwd = false

func main() {
	dryRun := exec.Command("ssh", append([]string{"-G"}, os.Args[1:]...)...)
	fullConfig, err := dryRun.Output()
	if err != nil {
		var stdErr []byte
		if ee, ok := err.(*exec.ExitError); ok {
			stdErr = ee.Stderr
		}
		os.Stderr.Write(stdErr)
		log.Fatalf("Failed to run SSH: %s", err)
	}
	userName := ""
	hostname := ""
	port := 0
	for _, line := range strings.Split(string(fullConfig), "\n") {
		if strings.HasPrefix(line, "user ") {
			userName = line[5:]
		}
		if strings.HasPrefix(line, "hostname ") {
			hostname = line[9:]
		}
		if strings.HasPrefix(line, "port ") {
			port, err = strconv.Atoi(line[5:])
			if err != nil {
				log.Fatalf("Failed to resolve port: %s", err)
			}
		}
	}
	curUser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %s", err)
	}

	remoteStub := exec.Command("ssh", append(os.Args[1:], "-M", "-S", path.Join(curUser.HomeDir, ".ssh", "%C.master"), RemoteStubName)...)
	remoteStdErr, err := remoteStub.StderrPipe()
	if err != nil {
		log.Fatalf("Failed to get ssh stderr: %s", err)
	}
	remoteStdOut, err := remoteStub.StdoutPipe()
	if err != nil {
		log.Fatalf("Failed to get ssh stdout: %s", err)
	}
	remoteStdIn, err := remoteStub.StdinPipe()
	if err != nil {
		log.Fatalf("Failed to get ssh stdin: %s", err)
	}

	err = remoteStub.Start()
	if err != nil {
		var stdErr []byte
		if ee, ok := err.(*exec.ExitError); ok {
			stdErr = ee.Stderr
		}
		os.Stderr.Write(stdErr)
		fullStdErr, _ := ioutil.ReadAll(remoteStdErr)
		log.Fatalf("Failed to run SSH: %s\n%s", err, fullStdErr)
	}

	go io.Copy(os.Stderr, remoteStdErr)
	stubReader := bufio.NewReader(remoteStdOut)
	remoteSocket, _, err := stubReader.ReadLine()
	if err != nil {
		allErr, _ := ioutil.ReadAll(remoteStdErr)
		log.Fatalf("Failed to read remote socket path from stub: %s\n%s", err, allErr)
	}

	listener, bindAddr, err := common.CreateSocket("")
	if err != nil {
		log.Fatalf("Failed to listen on socket %s: %s", bindAddr, err)
	}

	defer listener.Close()
	defer os.Remove(bindAddr)

	child := exec.Command("ssh", append([]string{"-o ExitOnForwardFailure yes", "-vvv", "-S", path.Join(curUser.HomeDir, ".ssh", "%C.master"), "-O", "forward", fmt.Sprintf("-R %s:%s", string(remoteSocket), bindAddr)}, os.Args[1:]...)...)
	out, err := child.Output()
	if err != nil {
		var stdErr []byte
		if ee, ok := err.(*exec.ExitError); ok {
			stdErr = ee.Stderr
		}
		os.Stderr.Write(stdErr)
		log.Fatalf("Failed to run SSH forwarding: %s\n%s", err, out)
	}

	_, err = fmt.Fprintln(remoteStdIn, "start")
	if err != nil {
		log.Fatalf("Failed to ack forwarding: %s", err)
	}

	for err == nil {
		client, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		realAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			io.Copy(client, realAgent)
			client.Close()
		}()
		msg := common.AgentForwardingNoticeMsg{Hostname: hostname, Port: uint32(port), Username: userName}
		if err = common.WriteControlPacket(realAgent, common.MsgAgentForwardingNotice, ssh.Marshal(msg)); err != nil {
			log.Fatalf("Failed to send message to agent: %s", err)
		}
		go func() {
			io.Copy(realAgent, client)
			if debugSSHFwd {
				log.Printf("Finished copying from client to real agent.")
			}
			realAgent.Close()
		}()
	}
}
