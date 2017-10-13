package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	guardianagent "github.com/StanfordSNR/guardian-agent"
	flags "github.com/jessevdk/go-flags"
)

const debugClient = true

type SSHCommand struct {
	UserHost string   `required:"true" positional-arg-name:"[user@]hostname"`
	Rest     []string `positional-arg-name:"[--] [command]" optional:"true"`
}

type options struct {
	guardianagent.CommonOptions

	StdinNull bool `short:"n" description:"Redirects stdin from /dev/null"`

	ForceTTY []bool `short:"t" description:"Forces TTY allocation"`

	SSHCommand SSHCommand `positional-args:"true" required:"true"`

	// Flags provided for compatibility with SCP (supporting only default values)
	DisableXForwarding bool `short:"x" hidden:"true"`

	// Flags provided for compatibility with Mosh (supporting only default values)
	ControlPath string `short:"S" hidden:"true" default:"none" choice:"none"`

	SSHOptions []string `short:"o" description:"SSH Options (partially supported)"`
}

func main() {
	var opts options
	var parser = flags.NewParser(&opts, flags.Default)
	parser.UnknownOptionHandler = func(option string, arg flags.SplitArgument, args []string) ([]string, error) {
		fmt.Fprintf(os.Stderr, "Unknown option: %s\n", option)
		return args, nil
	}

	_, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(255)
		}
	}

	var proxyCommand string
	for _, sshOption := range opts.SSHOptions {
		parts := strings.SplitN(sshOption, "=", 2)
		// These flags are supported for compatibility with SCP, but only default values are permitted.
		if parts[0] == "ForwardAgent" || parts[0] == "PermitLocalCommand" {
			if len(parts) < 2 || strings.ToLower(parts[1]) != "no" {
				fmt.Fprintf(os.Stderr, "Unsupported option: %s", strings.Join(parts, "="))
				os.Exit(255)
			}
			continue
		}

		if parts[0] == "ClearAllForwardings" {
			if len(parts) > 1 && strings.ToLower(parts[1]) != "yes" {
				fmt.Fprintf(os.Stderr, "Unsupported option: %s", strings.Join(parts, "="))
				os.Exit(255)
			}
			continue
		}

		if parts[0] == "ProxyCommand" {
			if len(parts) == 2 {
				proxyCommand = parts[1]
			}
			continue
		}

		fmt.Fprintf(os.Stderr, "Unsupported option: %s", sshOption)
		os.Exit(255)
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

	var host string
	host, opts.Port, opts.Username = guardianagent.ResolveRemote(parser, &opts.CommonOptions, opts.SSHCommand.UserHost)

	var cmd string
	if len(opts.SSHCommand.Rest) > 0 {
		cmd = strings.Join(opts.SSHCommand.Rest, " ")
	}

	proxyCommand = strings.Replace(proxyCommand, "%h", host, -1)
	proxyCommand = strings.Replace(proxyCommand, "%p", strconv.Itoa(opts.Port), -1)
	proxyCommand = strings.Replace(proxyCommand, "%r", opts.Username, -1)

	dc := guardianagent.DelegatedClient{
		HostPort:     fmt.Sprintf("%s:%d", host, opts.Port),
		Username:     opts.Username,
		Cmd:          cmd,
		ProxyCommand: proxyCommand,
		ForceTty:     len(opts.ForceTTY) == 2,
		StdinNull:    opts.StdinNull,
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
