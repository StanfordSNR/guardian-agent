// +build darwin dragonfly freebsd linux netbsd openbsd solaris

package guardianagent

import (
	"fmt"
	"net"
	"os"
	"path"

	"golang.org/x/sys/unix"
)

func CreateSocket(name string) (s *net.UnixListener, finalName string, err error) {
	if name == "" {
		finalName = path.Join(UserTempDir(), fmt.Sprintf(".guard.%d", os.Getpid()))
	} else {
		finalName = name
	}

	oldMask := unix.Umask(0177)
	conn, err := net.Listen("unix", finalName)
	s = conn.(*net.UnixListener)
	unix.Umask(oldMask)
	return
}
