package main

import (
	"fmt"
	"log"
	"os"
	"os/user"
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

	Username string `short:"l" description:"Specifies the user to log in as on the remote machine"`

	Port uint32 `short:"p" long:"port" description:"Port to connect to on the intermediary host" default:"22"`

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
	opts := options{}
	parser := flags.NewParser(&opts, flags.HelpFlag|flags.PassDoubleDash)
	parser.UnknownOptionHandler = func(option string, arg flags.SplitArgument, args []string) ([]string, error) {
		fmt.Fprintf(os.Stderr, "Unknown option: %s\n", option)
		return args, nil
	}

	guardianagent.ParseCommandLineOrDie(parser, &opts)

	var proxyCommand string
	for _, sshOption := range opts.SSHOptions {
		parts := strings.SplitN(sshOption, "=", 2)
		// These flags are supported for compatibility with SCP, but only default values are permitted.
		if parts[0] == "ForwardAgent" || parts[0] == "PermitLocalCommand" {
			if len(parts) < 2 || strings.ToLower(parts[1]) != "no" {
				fmt.Fprintf(os.Stderr, "%s: unsupported option: %s", os.Args[0], strings.Join(parts, "="))
				os.Exit(255)
			}
			continue
		}

		if parts[0] == "ClearAllForwardings" {
			if len(parts) > 1 && strings.ToLower(parts[1]) != "yes" {
				fmt.Fprintf(os.Stderr, "%s: unsupported option: %s", os.Args[0], strings.Join(parts, "="))
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

		fmt.Fprintf(os.Stderr, "%s: unsupported option: %s", os.Args[0], sshOption)
		os.Exit(255)
	}

	var host string
	host, opts.Port, opts.Username = resolveRemote(parser, &opts, opts.SSHCommand.UserHost)

	var cmd string
	if len(opts.SSHCommand.Rest) > 0 {
		cmd = strings.Join(opts.SSHCommand.Rest, " ")
	}

	proxyCommand = strings.Replace(proxyCommand, "%h", host, -1)
	proxyCommand = strings.Replace(proxyCommand, "%p", strconv.FormatUint(uint64(opts.Port), 10), -1)
	proxyCommand = strings.Replace(proxyCommand, "%r", opts.Username, -1)

	sshCmd := guardianagent.SSHCommand{
		HostPort:     fmt.Sprintf("%s:%d", host, opts.Port),
		Username:     opts.Username,
		Cmd:          cmd,
		ProxyCommand: proxyCommand,
		ForceTty:     len(opts.ForceTTY) == 2,
		StdinNull:    opts.StdinNull,
	}
	err := guardianagent.RunSSHCommand(sshCmd)
	if err == nil {
		return
	}
	log.Printf("%s: Failed to run %s on %s: %s", os.Args[0], cmd, host, err.Error())
	if ee, ok := err.(*ssh.ExitError); ok {
		if ee.Msg() != "" {
			fmt.Fprintln(os.Stderr, ee.Msg())
		}
		os.Exit(ee.ExitStatus())
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(255)

}

func resolveRemote(parser *flags.Parser, opts *options, userAndHost string) (host string, port uint32, username string) {
	sshCommandLine := []string{userAndHost}
	if !parser.FindOptionByLongName("port").IsSetDefault() {
		sshCommandLine = append(sshCommandLine, fmt.Sprintf("-p %d", opts.Port))
	}
	if parser.FindOptionByShortName('l').IsSet() {
		sshCommandLine = append(sshCommandLine, "-l", opts.Username)
	}

	host, port, username, err := guardianagent.ResolveHostParams("ssh", sshCommandLine)
	if err != nil {
		log.Printf("%s. Using fallback resolution.", sshCommandLine, err)
		return fallbackResolveRemote(opts, userAndHost)
	}
	return host, port, username
}

func fallbackResolveRemote(opts *options, userAndHost string) (host string, port uint32, username string) {
	userHost := strings.Split(userAndHost, "@")
	host = userHost[len(userHost)-1]
	if opts.Username != "" {
		username = opts.Username
	} else if len(userHost) > 1 {
		username = userHost[0]
	} else {
		curuser, err := user.Current()
		if err == nil {
			username = curuser.Username
		}
	}
	return host, opts.Port, username
}
