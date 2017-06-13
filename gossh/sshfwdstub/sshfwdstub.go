package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path"

	"github.com/dimakogan/ssh/gossh/common"
)

func main() {
	tmpDir, err := ioutil.TempDir("", "ssh-agent-guard")
	if err != nil {
		log.Fatalf("Failed to created tempdir: %s", err)
	}
	tempSocket := path.Join(tmpDir, fmt.Sprintf("guard.%d", os.Getpid()))
	_, err = fmt.Println(tempSocket)
	if err != nil {
		log.Fatalf("Failed to write temp dir location: %s", err)
	}
	reader := bufio.NewReader(os.Stdin)
	_, _, err = reader.ReadLine()
	if err != nil {
		log.Fatalf("Failed to read continuation from stdin: %s", err)
	}
	if _, err := os.Stat(tempSocket); os.IsNotExist(err) {
		log.Fatalf("Failed to find forwarded socket: %s", err)
	}

	permanentSocket := ""
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir != "" {
		permanentSocket = path.Join(dir, common.AgentGuardSockName)
	} else {
		curuser, err := user.Current()
		if err != nil {
			log.Fatalf("Failed to get user homedir: %s", err)
		}
		permanentSocket = path.Join(curuser.HomeDir, ".ssh", common.AgentGuardSockName)
	}

	if _, err := os.Stat(permanentSocket); err == nil {
		os.Remove(permanentSocket)
	}
	
	if err := os.Symlink(tempSocket, permanentSocket); err != nil {
		log.Fatalf("Failed to create symlink %s --> %s : %s", permanentSocket, tempSocket, err)
	}
	reader.ReadLine()
}
