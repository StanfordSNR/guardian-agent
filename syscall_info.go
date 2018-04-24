package guardianagent

import (
	"encoding/hex"
	"fmt"
	"path"
	"strings"
)

type SyscallInfo struct {
	Desc      string
	Name      string
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
	currentDirPath := ""
	argDescs := []string{}
	for i, arg := range args {
		switch arg := arg.Arg.(type) {
		case *Argument_IntArg:
			argDescs = append(argDescs, fmt.Sprintf("%d", arg.IntArg))
		case *Argument_StringArg:
			argDescs = append(argDescs, fmt.Sprintf("\"%s\"", arg.StringArg))
		case *Argument_BytesArg:
			bufPreview := hex.EncodeToString(arg.BytesArg)
			if len(arg.BytesArg) > 20 {
				bufPreview = hex.EncodeToString(arg.BytesArg[0:20]) + "..."
			}
			argDescs = append(argDescs, fmt.Sprintf("buffer of length %d [%s]", len(arg.BytesArg), bufPreview))
		case *Argument_OutBufferArg:
			continue
		case *Argument_FdArg:
			currentDirPath = arg.FdArg.GetPath()
			if currentDirPath == "" {
				argDescs = append(argDescs, fmt.Sprintf("fd #%d", arg.FdArg.GetFd()))
			} else {
				argDescs = append(argDescs, currentDirPath)
			}
			info.FilePaths = append(info.FilePaths, currentDirPath)
			continue
		case *Argument_PathArg:
			filePath := arg.PathArg
			if !path.IsAbs(filePath) {
				filePath = path.Join(currentDirPath, filePath)
			}
			if i > 0 {
				if _, prevIsFd := args[i-1].Arg.(*Argument_FdArg); prevIsFd {
					argDescs = argDescs[:len(argDescs)-1]
					info.FilePaths = info.FilePaths[:len(info.FilePaths)-1]
				}
			}
			argDescs = append(argDescs, fmt.Sprintf(filePath))
			info.FilePaths = append(info.FilePaths, filePath)
		}
	}
	info.Desc += strings.Join(argDescs, ", ") + ")" + cwdSuffix
	return &info
}
