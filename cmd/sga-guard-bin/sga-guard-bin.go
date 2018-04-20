package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"
	guardianagent "github.com/StanfordSNR/guardian-agent"
	flags "github.com/jessevdk/go-flags"
)

const debugClient = true

const configPath = "/etc/security/guardian-agent"

type Config struct {
	SSHAgent  string
	SSHAdd    string
	PKCS11Lib string
}

var (
	defaultConfig = Config{
		SSHAgent:  "/usr/bin/ssh-agent",
		SSHAdd:    "/usr/bin/ssh-add",
		PKCS11Lib: "/usr/local/lib/opensc-pkcs11.so",
	}
)

type SSHCommand struct {
	UserHost string `positional-arg-name:"[user@]hostname"`
}

type options struct {
	guardianagent.CommonOptions

	SSHProgram string `long:"ssh" description:"ssh program to run when setting up session" default:"ssh"`

	PolicyConfig string `long:"policy" description:"Policy config file" default:"$HOME/.ssh/sga_policy"`

	RemoteStubName string `long:"stub" description:"Remote stub executable path" default:"$SHELL -l -c \"exec sga-stub\""`

	PromptType string `long:"prompt" description:"Type of prompt to use." choice:"DISPLAY" choice:"TERMINAL" choice:"CONSOLE" default:"TERMINAL"`

	SSHCommand SSHCommand `positional-args:"true"`

	Foreground bool `short:"f"`
}

type incomingListener interface {
	Accept() (net.Conn, error)
	Close() error
}

func main() {
	var err error
	var opts options
	var parser = flags.NewParser(&opts, flags.HelpFlag|flags.PassDoubleDash)
	var sshOptions []string
	parser.UnknownOptionHandler = func(option string, arg flags.SplitArgument, args []string) ([]string, error) {
		val, isSet := arg.Value()
		sshFlagsWithValues := "bcDEeFIilLmOopQRWw"

		if isSet {
			sshOptions = append(sshOptions, fmt.Sprintf("-%s", option), val)
		} else if strings.Contains(sshFlagsWithValues, option) {
			sshOptions = append(sshOptions, fmt.Sprintf("-%s", option), args[0])
			args = args[1:]
		} else {
			sshOptions = append(sshOptions, fmt.Sprintf("-%s", option))
		}
		return args, nil
	}

	guardianagent.ParseCommandLineOrDie(parser, &opts)

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

	var conf Config
	if _, err := toml.DecodeFile(configPath, &conf); err != nil {
		conf = defaultConfig
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
	originalVt := uint(0)
	if opts.PromptType == "CONSOLE" {
		if !opts.Foreground {
			child := exec.Command(os.Args[0], append([]string{"-f"}, os.Args[1:]...)...)
			child.Start()
			os.Exit(0)
		}

		newVt, _, err := guardianagent.Switchvt()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to switch to new vt: %s", err)
			os.Exit(255)
		}
		originalVt, err = guardianagent.FocusVT(newVt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to focus to new vt: %s", err)
			os.Exit(255)
		}
		fmt.Fprintf(os.Stdout, "Running agent on /dev/tty%d\n", newVt)
		ag, err = guardianagent.NewGuardian(opts.PolicyConfig, guardianagent.Console)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(255)
	}

	var listener incomingListener
	if opts.SSHCommand.UserHost != "" {
		sshFwd := guardianagent.NewSSHFwd(opts.SSHProgram, sshOptions, opts.SSHCommand.UserHost, opts.RemoteStubName)

		fmt.Fprintf(os.Stderr, "Setting up forwarding...\n")
		if err = sshFwd.SetupForwarding(); err != nil {
			fmt.Fprintf(os.Stderr, "%s", err)
			os.Exit(255)
		}

		fmt.Fprintf(os.Stderr, "Forwarding to %s setup successfully. Waiting for incoming requests...\n", sshFwd.RemoteReadableName)
		listener = sshFwd
	} else {
		euid := syscall.Geteuid()
		ruid := syscall.Getuid()
		syscall.Setreuid(euid, euid)

		tempDir, err := ioutil.TempDir(guardianagent.UserTempDir(), "ssh-agent")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create tempdir ssh-agent: %s", err)
			os.Exit(255)
		}
		agentSockPath := path.Join(tempDir, "ssh-agent-sock")
		realAgent := exec.Command(conf.SSHAgent, "-a", agentSockPath)
		realAgent.Env = []string{}
		output, err := realAgent.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to run ssh-agent: %s, %s", err, output)
			os.Exit(255)
		}
		os.Setenv("SSH_AUTH_SOCK", agentSockPath)

		sshAdd := exec.Command(conf.SSHAdd, "-s", conf.PKCS11Lib)
		sshAdd.Env = []string{fmt.Sprintf("SSH_AUTH_SOCK=%s", agentSockPath)}
		sshAdd.Stdin = os.Stdin
		sshAdd.Stdout = os.Stdout
		sshAdd.Stderr = os.Stderr
		err = sshAdd.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to run ssh-add: %s", err)
			os.Exit(255)
		}

		syscall.Setreuid(ruid, euid)
		log.Printf("uid: %d, euid: %d\n", syscall.Getuid(), syscall.Geteuid())

		rawListener, bindAddr, err := guardianagent.CreateSocket("")
		os.Chown(bindAddr, os.Getuid(), os.Getegid())
		listener = guardianagent.UDSListener{rawListener}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to listen on socket %s: %s", bindAddr, err)
			os.Exit(255)
		}
		err = guardianagent.CreatAgentGuardSocketLink(bindAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create permanent guardian agent socket: %s", err)
			os.Exit(255)
		}
	}

	ints := make(chan os.Signal, 1)
	signal.Notify(ints, os.Interrupt)
	shutdown := false
	go func() {
		for range ints {
			fmt.Fprintf(os.Stderr, "Got Interrupt signal, shutting down...\n")
			shutdown = true
			listener.Close()
		}
	}()

	if opts.PromptType == "CONSOLE" {
		guardianagent.FocusVT(originalVt)
	}

	var c net.Conn
	for {
		c, err = listener.Accept()
		if shutdown {
			fmt.Fprintln(os.Stderr, "Shutdown complete\n")
			os.Exit(0)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error forwarding: %s\n", err)
			os.Exit(255)
		}
		go func() {
			if err = ag.HandleConnection(c); err != nil {
				fmt.Fprintf(os.Stderr, "Error forwarding: %s\n", err)
			}
		}()
	}
}
