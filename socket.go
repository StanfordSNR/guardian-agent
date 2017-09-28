// +build darwin dragonfly freebsd linux netbsd openbsd solaris

package common

import (
	"fmt"
	"net"
	"os"
	"path"

	"golang.org/x/sys/unix"
)

func CreateSocket(name string) (s net.Listener, finalName string, err error) {
	if name == "" {
		finalName = path.Join(UserTempDir(), fmt.Sprintf(".guard.%d", os.Getpid()))
	} else {
		finalName = name
	}

	oldMask := unix.Umask(0177)
	s, err = net.Listen("unix", finalName)
	unix.Umask(oldMask)
	return
}
