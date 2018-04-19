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

	if err = guardianagent.CreatAgentGuardSocketLink(tempSocket); err != nil {
		log.Fatal(err)
	}
	fmt.Println("OK")
	reader.ReadLine()
}
