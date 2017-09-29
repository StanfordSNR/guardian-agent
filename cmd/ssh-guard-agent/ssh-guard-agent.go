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

	"golang.org/x/crypto/ssh"

	guardianagent "github.com/StanfordSNR/guardian-agent"
	"github.com/kballard/go-shellquote"
)

const debugClient = true

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-AdN] [-p port] [-prompt=DISPLAY|TERMINAL] [user@]hostname [command]\n", os.Args[0])
		flag.PrintDefaults()
	}

	var debug bool
	flag.BoolVar(&debug, "debug", false, "Debug Mode")

	var port int
	flag.IntVar(&port, "p", 22, "Port to connect to on the remote host.")

	var sshCmd string
	flag.StringVar(&sshCmd, "ssh", "ssh", "ssh command to run when setting up session")

	var sshArgs string
	flag.StringVar(&sshArgs, "ssh_args", "", "additional arguments to pass to ssh command")

	var delegatedClient bool
	flag.BoolVar(&delegatedClient, "d", false, "Delegate authentication to ssh agent guard.")

	var forwardAgent bool
	flag.BoolVar(&forwardAgent, "A", false, "(Secure) SSH Agent Forwarding.")

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
		cmd = strings.Join(flag.Args()[1:], " ")
	}

	if debugClient {
		log.Printf("Host: %s, Port: %d, User: %s\n", host, port, username)
	}

	if !delegatedClient && !forwardAgent {
		fmt.Fprintln(os.Stderr, "Either -A (forwarding) or -d (delegation) must be specified")
		os.Exit(1)
	}

	if delegatedClient {
		if sshCmd != "ssh" {
			log.Fatalf("--ssh flag not supported when running in delegated mode (-d)")
		}
		if forwardAgent {
			log.Fatalf("agent forwarding (-A) is not supported in delegated mode (-d)")
		}
		if noCommand {
			log.Fatalf("no command (-N) is not supported in delegated mode (-d)")
		}
		dc := guardianagent.DelegatedClient{
			HostPort: fmt.Sprintf("%s:%d", host, port),
			Username: username,
			Cmd:      cmd,
		}
		err = dc.Run()
		if err == nil {
			return
		}
		log.Printf(err.Error())
		if ee, ok := err.(*ssh.ExitError); ok {
			if ee.Msg() != "" {
				fmt.Fprintln(os.Stderr, ee.Msg())
			}
			os.Exit(ee.ExitStatus())
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(255)
	}

	if forwardAgent {
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
		sshArgsArray, err := shellquote.Split(sshArgs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse ssh_args: %s", err)
			os.Exit(255)
		}
		sshFwd := guardianagent.SSHFwd{
			SSHCmd:         sshCmd,
			SSHArgs:        sshArgsArray,
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
}
