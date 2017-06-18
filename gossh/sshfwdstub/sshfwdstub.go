package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path"

	"github.com/dimakogan/ssh/gossh/common"
)

func main() {
	tempSocket := path.Join(common.UserTempDir(), fmt.Sprintf("guard.%d", os.Getpid()))
	_, err := fmt.Println(tempSocket)
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

	permanentSocket := path.Join(common.UserRuntimeDir(), common.AgentGuardSockName)

	if _, err := os.Stat(permanentSocket); err == nil {
		os.Remove(permanentSocket)
	}

	if err := os.Symlink(tempSocket, permanentSocket); err != nil {
		log.Fatalf("Failed to create symlink %s --> %s : %s", permanentSocket, tempSocket, err)
	}
	reader.ReadLine()
}
