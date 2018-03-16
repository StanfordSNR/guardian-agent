package guardianagent

// #cgo LDFLAGS:  -l:syscalls.o
// #include <proto/syscalls.hh>
import "C"
import (
	"unsafe"

	proto "github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
)

func GetSyscallConfig() (*Syscalls, error) {
	syscalls := Syscalls{}
	binaryProto := C.GoBytes(unsafe.Pointer(&C._binary_syscalls_binproto_start),
		C.int(uintptr(unsafe.Pointer(&C._binary_syscalls_binproto_end))-uintptr(unsafe.Pointer(&C._binary_syscalls_binproto_start))))
	if err := proto.Unmarshal(binaryProto, &syscalls); err != nil {
		return nil, errors.Wrapf(err, "Failed to parse config")
	}
	return &syscalls, nil
}
