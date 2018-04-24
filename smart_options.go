package guardianagent

import (
	"fmt"
	"path"
	"strings"
)

type SmartOption interface {
	Prompt() (option string, approved string)
	IsAllowed(scope Scope, process *Process, syscallInfo *SyscallInfo) (isOk bool, approved string)
}

type fileForProcess struct {
	scope   Scope
	process *Process
	file    string
}

type parentDirForProcess struct {
	scope   Scope
	process *Process
	dir     string
}

type parentDirForParentProcess struct {
	scope Scope
	ppid  uint32
	dir   string
}

func IsFileOperation(syscallInfo *SyscallInfo) bool {
	fileOps := map[string]bool{"open": true, "stat": true, "openat": true, "access": true, "lstat": true, "unlink": true, "rmdir": true,
		"mkdir": true, "unlinkat": true, "chmod": true, "fchmod": true, "fchmodat": true}
	return fileOps[syscallInfo.Name]
}

func (opt fileForProcess) Prompt() (option string, approved string) {
	return "Allow all future access to this file by this process", "All future requests to this file by this process will be APPROVED"
}

func (opt fileForProcess) IsAllowed(scope Scope, process *Process, syscallInfo *SyscallInfo) (isOk bool, approved string) {
	if scope != opt.scope || *process != *opt.process {
		return false, ""
	}

	if IsFileOperation(syscallInfo) && syscallInfo.FilePaths[0] == opt.file {
		return true, "AUTO APPROVED"
	}
	return false, ""
}

func (opt parentDirForProcess) Prompt() (option string, approved string) {
	return fmt.Sprintf("Allow all future access to the directory %s by this process", opt.dir), "All future requests to this directory by this process will be APPROVED"
}

func (opt parentDirForProcess) IsAllowed(scope Scope, process *Process, syscallInfo *SyscallInfo) (isOk bool, approved string) {
	if scope != opt.scope || *process != *opt.process {
		return false, ""
	}

	if IsFileOperation(syscallInfo) && strings.HasPrefix(syscallInfo.FilePaths[0], opt.dir) {
		return true, "AUTO APPROVED"
	}
	return false, ""
}

func (opt parentDirForParentProcess) Prompt() (option string, approved string) {
	return fmt.Sprintf("Allow all future access to the directory %s by this process and its children", opt.dir),
		"All future requests to this directory by this process and its children will be APPROVED"
}

func (opt parentDirForParentProcess) IsAllowed(scope Scope, process *Process, syscallInfo *SyscallInfo) (isOk bool, approved string) {
	if scope != opt.scope || (process.Ppid != opt.ppid && process.Pid != opt.ppid) {
		return false, ""
	}

	if IsFileOperation(syscallInfo) && strings.HasPrefix(syscallInfo.FilePaths[0], opt.dir) {
		return true, "AUTO APPROVED"
	}
	return false, ""
}

func GetSmartOptions(scope Scope, process *Process, syscallInfo *SyscallInfo) []SmartOption {
	options := []SmartOption{}
	if IsFileOperation(syscallInfo) {
		options = append(options,
			fileForProcess{scope: scope, process: process, file: syscallInfo.FilePaths[0]},
			parentDirForProcess{scope: scope, process: process, dir: path.Dir(syscallInfo.FilePaths[0]) + "/"},
			parentDirForParentProcess{scope: scope, ppid: process.Pid, dir: path.Dir(syscallInfo.FilePaths[0]) + "/"})
	}
	return options
}
