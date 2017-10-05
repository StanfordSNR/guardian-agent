package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"runtime"
	"strings"

	guardianagent "github.com/StanfordSNR/guardian-agent"
)

const debugClient = true

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s  [options] [user@]hostname [SSH options] [command]\n", os.Args[0])
		flag.PrintDefaults()
	}

	var debug bool
	flag.BoolVar(&debug, "debug", false, "Debug Mode")

	var port int
	flag.IntVar(&port, "p", 22, "Port to connect to on the remote host.")

	var sshProgram string
	flag.StringVar(&sshProgram, "ssh", "ssh", "ssh program to run when setting up session")

	var noCommand bool
	flag.BoolVar(&noCommand, "N", false, "Do not execute Commands. Useful for standalone SSH Agent Forwarding.")

	var policyConfig string
	flag.StringVar(&policyConfig, "policy", "$HOME/.ssh/agent_policies", "Policy config file")

	var remoteStubName string
	flag.StringVar(&remoteStubName, "stub", "ssh-fwd-stub", "Remote stub executable path")

	var promptType string
	flag.StringVar(&promptType, "prompt", "", "Type of prompt to use: `DISPLAY|TERMINAL`")

	var logFile string
	flag.StringVar(&logFile, "logfile", "", "log filename")

	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(255)
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if debug {
		if logFile == "" {
			log.SetOutput(os.Stderr)
		} else {
			f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to open log file: %s", err)
				os.Exit(255)
			}
			log.SetOutput(f)
		}
	} else {
		log.SetOutput(ioutil.Discard)
	}

	curuser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %s", err)
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

	var cmd string
	if flag.NArg() >= 2 {
		cmdArgs := flag.Args()[1:]
		if cmdArgs[0] == "--" {
			cmdArgs = cmdArgs[1:]
		}
		cmd = strings.Join(cmdArgs, " ")
	}

	policyConfig = os.ExpandEnv(policyConfig)
	var ag *guardianagent.Agent
	if noCommand && promptType != "DISPLAY" {
		ag, err = guardianagent.NewGuardian(policyConfig, guardianagent.Terminal)
	} else {
		if (runtime.GOOS == "linux") && (os.Getenv("DISPLAY") == "") {
			fmt.Fprintf(os.Stderr, "DISPLAY must be set for user prompts.\nEither set the DISPLAY environment variable or use -N.")
			os.Exit(255)
		}
		ag, err = guardianagent.NewGuardian(policyConfig, guardianagent.Display)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(255)
	}
	sshFwd := guardianagent.SSHFwd{
		SSHProgram:     sshProgram,
		Host:           host,
		Port:           port,
		Username:       username,
		RemoteStubName: remoteStubName,
	}

	if err = sshFwd.SetupForwarding(); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(255)
	}

	done := false
	if !noCommand {
		go func() {
			sshFwd.Run(cmd)
			done = true
			sshFwd.Close()
		}()
	} else {
		fmt.Println("Listening for incoming ssh agent requests...")
	}

	var c net.Conn
	for {
		c, err = sshFwd.Accept()
		if err != nil {
			if !done {
				log.Printf("Error forwarding: %s", err)
				os.Exit(255)
			}
			break
		}
		go func() {
			if err = ag.HandleConnection(c); err != nil {
				log.Printf("Error forwarding: %s", err)
			}
		}()
	}
}
