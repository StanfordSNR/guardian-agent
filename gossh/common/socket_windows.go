// +build windows

package common

import (
	"fmt"
	"math/rand"
	"net"
	"path"

	"os"

	npipe "gopkg.in/natefinch/npipe.v2"
)

func CreateSocket(name string) (s net.Listener, finalName string, err error) {
	if name == "" {
		finalName = path.Join(`\\.\pipe`, fmt.Sprintf("%d.%d", rand.Int63(), os.Getpid()))
	} else {
		finalName = name
	}
	s, err = npipe.Listen(finalName)
	return
}
