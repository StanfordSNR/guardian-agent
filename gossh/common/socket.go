// +build darwin dragonfly freebsd linux netbsd openbsd solaris

package common

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"

	"golang.org/x/sys/unix"
)

func CreateSocket(name string) (s net.Listener, finalName string, err error) {
	if name == "" {
		tempDir, err := ioutil.TempDir("", "ssh-guard-")
		if err != nil {
			log.Fatalf("Failed creating temp directory: %s", err)
		}
		finalName = path.Join(tempDir, fmt.Sprintf("guard.%d", os.Getpid()))
	} else {
		finalName = name
	}

	oldMask := unix.Umask(0177)
	s, err = net.Listen("unix", finalName)
	unix.Umask(oldMask)
	return
}
