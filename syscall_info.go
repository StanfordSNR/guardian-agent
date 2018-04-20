package guardianagent

import (
	"encoding/hex"
	"fmt"
)

type SyscallInfo struct {
	Desc      string
	Name      string
	DirFds    []string
	FilePaths []string
}

func NewSyscallInfo(op *Operation) *SyscallInfo {
	info := SyscallInfo{}

	var spec *SyscallSpec
	syscallsConf, err := GetSyscallConfig()
	if err == nil {
		for i := range syscallsConf.GetSyscall() {
			if syscallsConf.Syscall[i].GetNum() == op.GetSyscallNum() {
				spec = syscallsConf.Syscall[i]
			}
		}
	}
	if spec != nil {
		info.Name = spec.Name
		info.Desc = spec.Name + "("
	} else {
		info.Desc = fmt.Sprintf("syscall #%d (", op.SyscallNum)
	}
	cwdSuffix := ""
	args := op.GetArgs()
	if spec.GetAddFdCwd() {
		dirPath := args[0].GetDirFdArg().GetPath()
		cwdSuffix = fmt.Sprintf("\nrelative to dir: %s", dirPath)
		info.DirFds = append(info.DirFds, dirPath)
		args = args[1:]
	}
	for i, arg := range args {
		if i < len(spec.GetParams()) {
			info.Desc += spec.GetParams()[i].GetName() + ": "
		}
		switch arg := arg.Arg.(type) {
		case *Argument_IntArg:
			info.Desc += fmt.Sprintf("%d", arg.IntArg)
		case *Argument_StringArg:
			info.Desc += fmt.Sprintf("\"%s\"", arg.StringArg)
			info.FilePaths = append(info.FilePaths, arg.StringArg)
		case *Argument_BytesArg:
			bufPreview := hex.EncodeToString(arg.BytesArg)
			if len(arg.BytesArg) > 20 {
				bufPreview = hex.EncodeToString(arg.BytesArg[0:20]) + "..."
			}
			info.Desc += fmt.Sprintf("buffer of length %d [%s]", len(arg.BytesArg), bufPreview)
		case *Argument_OutBufferArg:
			info.Desc += fmt.Sprintf("buffer of length %d", arg.OutBufferArg.GetLen())
		case *Argument_FdArg:
			info.Desc += fmt.Sprintf("fd #%d", arg.FdArg.GetFd())
		case *Argument_DirFdArg:
			info.Desc += fmt.Sprintf("[%s]", arg.DirFdArg.GetPath())
			info.DirFds = append(info.DirFds, arg.DirFdArg.GetPath())
		}
		if i < len(args)-1 {
			info.Desc += ", "
		}
	}
	info.Desc += ")" + cwdSuffix
	return &info
}
