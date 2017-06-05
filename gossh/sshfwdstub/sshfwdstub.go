package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path"
)

func main() {
	dir, err := ioutil.TempDir("", "ssh-agent-guard")
	if err != nil {
		log.Fatalf("Failed to created tempdir: %s", err)
	}
	tempSocket := path.Join(dir, fmt.Sprintf("guard.%d", os.Getpid()))
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
	curUser, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user: %s", err)
	}
	permanentSocket := path.Join(curUser.HomeDir, ".ssh", "agent-guard.sock")
	if _, err := os.Stat(permanentSocket); err == nil {
		os.Remove(permanentSocket)
	}
	if os.Symlink(tempSocket, permanentSocket) != nil {
		log.Fatalf("Failed to create symlink %s --> %s : %s", permanentSocket, tempSocket, err)
	}
	reader.ReadLine()
}
