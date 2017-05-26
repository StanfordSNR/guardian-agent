package main

import (
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/crypto/ssh"

	"net"

	"strconv"

	"github.com/dimakogan/ssh/gossh/common"
)

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

	var bindAddr string
	listener, bindAddr, err := common.CreateSocket("")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	child := exec.Command("ssh", append([]string{"-o ExitOnForwardFailure yes", "-A"}, os.Args[1:]...)...)
	env, err := common.ReplaceSSHAuthSockEnv(os.Environ(), bindAddr)
	if err != nil {
		log.Fatal(err)
	}
	child.Env = env

	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	stopped := false
	if err = child.Start(); err != nil {
		log.Fatalf("Failed to execute child process: %s", err)
	}
	go func() {
		if err = child.Wait(); err != nil {
			log.Printf("Failed to execute child process: %s", err)
		}
		stopped = true
		listener.Close()
	}()
	for err == nil {
		client, err := listener.Accept()
		if stopped {
			break
		}
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
			realAgent.Close()
		}()
	}
}
