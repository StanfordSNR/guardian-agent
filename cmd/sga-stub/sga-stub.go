package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path"

	"github.com/StanfordSNR/guardian-agent"
)

func main() {
	tempSocket := path.Join(guardianagent.UserTempDir(), fmt.Sprintf("guard.%d", os.Getpid()))
	defer os.Remove(tempSocket)
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

	permanentSocket := path.Join(guardianagent.UserRuntimeDir(), guardianagent.AgentGuardSockName)

	if _, err := os.Lstat(permanentSocket); err == nil {
		err = os.Remove(permanentSocket)
		if err != nil {
			log.Fatalf("Failed to remove old permanent socket: %s", err)
		}
	}

	if err := os.Symlink(tempSocket, permanentSocket); err != nil {
		log.Fatalf("Failed to create symlink %s --> %s : %s", permanentSocket, tempSocket, err)
	}
	fmt.Println("OK")
	reader.ReadLine()
}
