package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"strings"

	"golang.org/x/crypto/ssh"

	guardianagent "github.com/StanfordSNR/guardian-agent"
)

const debugClient = true

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [user@]hostname [command]\n", os.Args[0])
		flag.PrintDefaults()
	}

	var debug bool
	flag.BoolVar(&debug, "debug", false, "Debug Mode")

	var port int
	flag.IntVar(&port, "p", 22, "Port to connect to on the remote host.")

	var logFile string
	flag.StringVar(&logFile, "logfile", "", "log filename")

	var stdinNull bool
	flag.BoolVar(&stdinNull, "n", false, "Redirects stdin from /dev/null")

	var forceTty bool
	flag.BoolVar(&forceTty, "tt", false, "Forces TTY allocation")

	// Flags provided for compatibility with SCP (supporting only default values)
	var disableXForwarding bool
	flag.BoolVar(&disableXForwarding, "x", true, "Disable X11 Forwarding (always on)")

	var oForwardAgent string
	flag.StringVar(&oForwardAgent, "oForwardAgent", "no", "Should provide (standard) SSH Agent forwarding (always off)")

	var oPermitLocalCommand string
	flag.StringVar(&oPermitLocalCommand, "oPermitLocalCommand", "no", "Allow local command execution (always off)")

	var oClearAllForwardings string
	flag.StringVar(&oClearAllForwardings, "oClearAllForwardings", "yes", "Ignore all port forwarding from configuration file (always on)")

	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(255)
	}

	if oForwardAgent != "no" {
		fmt.Fprintf(os.Stderr, "Unsupported option: 'ForwardAgent=%s'", oForwardAgent)
		os.Exit(255)
	}

	if oPermitLocalCommand != "no" {
		fmt.Fprintf(os.Stderr, "Unsupported option: 'PermitLocalCommand=%s'", oPermitLocalCommand)
		os.Exit(255)
	}

	if oClearAllForwardings != "yes" {
		fmt.Fprintf(os.Stderr, "Unsupported optioni 'ClearAllForwardings=%s'", oClearAllForwardings)
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

	dc := guardianagent.DelegatedClient{
		HostPort:  fmt.Sprintf("%s:%d", host, port),
		Username:  username,
		Cmd:       cmd,
		ForceTty:  forceTty,
		StdinNull: stdinNull,
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
