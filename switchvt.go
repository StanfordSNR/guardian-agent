package guardianagent

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const VT_OPENQRY = 0x5600    /* find available vt */
const VT_GETSTATE = 0x5603   /* get global vt state info */
const VT_ACTIVATE = 0x5606   /* make vt active */
const VT_WAITACTIVE = 0x5607 /* wait for vt active */

var (
	NewVt = uint(0)
)

func Switchvt() (uint, *os.File, error) {
	fmt.Println("Hi!")

	tty, err := os.Open("/dev/console")
	if err != nil {
		return 0, nil, fmt.Errorf("Failed to open /dev/console: %s", err)
	}
	defer tty.Close()
	var vtNum uint
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, tty.Fd(), VT_OPENQRY, uintptr(unsafe.Pointer(&vtNum)))
	if e != 0 {
		return 0, nil, fmt.Errorf("VT_OPENQRY Ioctl failed: %d", e)
	}
	log.Printf("Free tty: %d\n", vtNum)

	if _, err = unix.Setsid(); err != nil {
		return 0, nil, fmt.Errorf("Setsid failed: %s", err)
	}
	os.Stdin.Close()
	stdinHandle, err := syscall.Open(fmt.Sprintf("/dev/tty%d", vtNum), unix.O_RDWR, 0)
	if err != nil {
		return 0, nil, fmt.Errorf("Open new tty failed: %s", err)
	}
	log.Printf("New tty fd: %d\n", stdinHandle)
	os.Stdin = os.NewFile(uintptr(stdinHandle), "/dev/stdin")

	oldStdout, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		return 0, nil, fmt.Errorf("Failed to save old stdout: %s", err)
	}
	os.Stdout.Close()
	stdoutHandle, err := syscall.Dup(int(os.Stdin.Fd()))
	os.Stdout = os.NewFile(uintptr(stdoutHandle), "/dev/stdout")

	os.Stderr.Close()
	stderrHandle, err := syscall.Dup(int(os.Stdin.Fd()))
	os.Stderr = os.NewFile(uintptr(stderrHandle), "/dev/stderr")

	//fmt.Fprintf(os.Stderr, "Hi new stderr (:\n")
	//fmt.Fprintf(os.Stdout, "Hi new stdout (:\n")
	//fmt.Fprintf(os.Stdout, "Stdin, are you here?\n")
	NewVt = vtNum
	return vtNum, oldStdout, nil
}

type vt_stat struct {
	v_active uint16 /* active vt */
	v_signal uint16 /* signal to send */
	v_state  uint16 /* vt bitmask */
}

func FocusVT(vt uint) (uint, error) {
	tty, err := os.Open("/dev/console")
	if err != nil {
		return 0, fmt.Errorf("Failed to open /dev/console: %s", err)
	}

	stat := vt_stat{}
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(tty.Fd()), VT_GETSTATE, uintptr(unsafe.Pointer(&stat)))
	if e != 0 {
		return 0, fmt.Errorf("VT_GETSTATE Ioctl failed: %d", e)
	}

	_, _, e = syscall.Syscall(syscall.SYS_IOCTL, uintptr(tty.Fd()), VT_ACTIVATE, uintptr(vt))
	if e != 0 {
		return 0, fmt.Errorf("VT_ACTIVATE Ioctl failed: %d", e)
	}
	_, _, e = syscall.Syscall(syscall.SYS_IOCTL, uintptr(tty.Fd()), VT_WAITACTIVE, uintptr(vt))
	if e != 0 {
		return 0, fmt.Errorf("VT_WAITACTIVE Ioctl failed: %d", e)
	}

	return uint(stat.v_active), nil
}
