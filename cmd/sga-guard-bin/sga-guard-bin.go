package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/user"
	"runtime"
	"strings"

	guardianagent "github.com/StanfordSNR/guardian-agent"
	flags "github.com/jessevdk/go-flags"
)

const debugClient = true

type SSHCommand struct {
	UserHost string `required:"true" positional-arg-name:"[user@]hostname"`
	Rest     []string
}

type options struct {
	Debug bool `long:"debug" description:"Show debug information"`

	Port uint `short:"p" long:"port" description:"Port to connect to on the intermediary host" default:"22"`

	SSHProgram string `long:"ssh" description:"ssh program to run when setting up session" default:"ssh"`

	NoCommand bool `short:"N" description:"Do not execute Commands. Useful for standalone SSH Agent Forwarding"`

	PolicyConfig string `long:"policy" description:"Policy config file" default:"$HOME/.ssh/sga_policy"`

	RemoteStubName string `long:"stub" description:"Remote stub executable path" default:"sga-stub"`

	PromptType string `long:"prompt" description:"Type of prompt to use: DISPLAY|TERMINAL" choice:"DISPLAY" choice:"TERMINAL" choice:""`

	LogFile string `long:"log" description:"log file"`

	SSHCommand SSHCommand `positional-args:"true"`
}

func main() {
	var opts options
	var parser = flags.NewParser(&opts, flags.Default)
	var sshOptions []string
	parser.UnknownOptionHandler = func(option string, arg flags.SplitArgument, args []string) ([]string, error) {
		val, isSet := arg.Value()
		sshFlagsWithValues := "bcDEeFIiLlmOoQRWw"

		if isSet {
			sshOptions = append(sshOptions, fmt.Sprintf("-%s %s", option, val))
		} else if strings.Contains(sshFlagsWithValues, option) {
			sshOptions = append(sshOptions, fmt.Sprintf("-%s %s", option, args[0]))
			args = args[1:]
		} else {
			sshOptions = append(sshOptions, fmt.Sprintf("-%s", option))
		}
		return args, nil
	}

	_, err := parser.Parse()

	if err != nil {
		fmt.Fprintf(os.Stderr, parser.Usage)
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(255)
		}
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if opts.Debug {
		if opts.LogFile == "" {
			log.SetOutput(os.Stderr)
		} else {
			f, err := os.OpenFile(opts.LogFile, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
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

	userHost := strings.Split(opts.SSHCommand.UserHost, "@")
	var username string
	var host string
	if len(userHost) > 1 {
		username, host = userHost[0], userHost[1]
	} else {
		username = curuser.Username
		host = userHost[0]
	}

	var cmd string
	if len(opts.SSHCommand.Rest) >= 1 {
		cmd = strings.Join(opts.SSHCommand.Rest, " ")
	}

	opts.PolicyConfig = os.ExpandEnv(opts.PolicyConfig)
	var ag *guardianagent.Agent
	if opts.NoCommand && opts.PromptType != "DISPLAY" {
		ag, err = guardianagent.NewGuardian(opts.PolicyConfig, guardianagent.Terminal)
	} else {
		if (runtime.GOOS == "linux") && (os.Getenv("DISPLAY") == "") {
			fmt.Fprintf(os.Stderr, "DISPLAY must be set for user prompts.\nEither set the DISPLAY environment variable or use -N.")
			os.Exit(255)
		}
		ag, err = guardianagent.NewGuardian(opts.PolicyConfig, guardianagent.Display)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(255)
	}
	sshFwd := guardianagent.SSHFwd{
		SSHProgram:     opts.SSHProgram,
		SSHArgs:        sshOptions,
		Host:           host,
		Port:           opts.Port,
		Username:       username,
		RemoteStubName: opts.RemoteStubName,
	}

	if err = sshFwd.SetupForwarding(); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(255)
	}

	done := false
	if !opts.NoCommand {
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
