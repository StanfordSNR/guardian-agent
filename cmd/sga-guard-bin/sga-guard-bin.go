package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"runtime"
	"strings"

	guardianagent "github.com/StanfordSNR/guardian-agent"
	flags "github.com/jessevdk/go-flags"
)

const debugClient = true

type SSHCommand struct {
	UserHost string `required:"true" positional-arg-name:"[user@]hostname"`
}

type options struct {
	guardianagent.CommonOptions

	SSHProgram string `long:"ssh" description:"ssh program to run when setting up session" default:"ssh"`

	PolicyConfig string `long:"policy" description:"Policy config file" default:"$HOME/.ssh/sga_policy"`

	RemoteStubName string `long:"stub" description:"Remote stub executable path" default:"$SHELL -l -c \"exec sga-stub\""`

	PromptType string `long:"prompt" description:"Type of prompt to use." choice:"DISPLAY" choice:"TERMINAL" default:"DISPLAY"`

	SSHCommand SSHCommand `positional-args:"true" required:"true"`
}

func main() {
	var opts options
	var parser = flags.NewParser(&opts, flags.Default)
	var sshOptions []string
	parser.UnknownOptionHandler = func(option string, arg flags.SplitArgument, args []string) ([]string, error) {
		val, isSet := arg.Value()
		sshFlagsWithValues := "bcDEeFIiLmOopQRWw"

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

	readableName := opts.SSHCommand.UserHost
	if parser.FindOptionByShortName('l').IsSet() {
		readableName = opts.Username + "@" + readableName
		sshOptions = append(sshOptions, "-l", opts.Username)
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

	opts.PolicyConfig = os.ExpandEnv(opts.PolicyConfig)
	var ag *guardianagent.Agent
	if opts.PromptType == "DISPLAY" {
		if (runtime.GOOS == "linux") && (os.Getenv("DISPLAY") == "") {
			fmt.Fprintln(os.Stderr, `DISPLAY environment variable is not set. Using terminal for user prompts.`)
			opts.PromptType = "TERMINAL"
		} else {
			ag, err = guardianagent.NewGuardian(opts.PolicyConfig, guardianagent.Display)
		}
	}
	if opts.PromptType == "TERMINAL" {
		ag, err = guardianagent.NewGuardian(opts.PolicyConfig, guardianagent.Terminal)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(255)
	}
	sshFwd := guardianagent.SSHFwd{
		SSHProgram:         opts.SSHProgram,
		SSHArgs:            sshOptions,
		Host:               opts.SSHCommand.UserHost,
		RemoteReadableName: readableName,
		RemoteStubName:     opts.RemoteStubName,
	}

	if err = sshFwd.SetupForwarding(); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(255)
	}

	fmt.Printf("Listening for incoming Guardian Agent requests from %s...\n", readableName)

	var c net.Conn
	for {
		c, err = sshFwd.Accept()
		if err != nil {
			log.Printf("Error forwarding: %s", err)
			os.Exit(255)
		}
		go func() {
			if err = ag.HandleConnection(c); err != nil {
				log.Printf("Error forwarding: %s", err)
			}
		}()
	}
}
