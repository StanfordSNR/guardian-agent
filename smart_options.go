package guardianagent

type SmartOption interface {
	Prompt() (option string, approved string)
	IsAllowed(scope Scope, process *Process, syscallInfo *SyscallInfo) (isOk bool, approved string)
}

type fileForProcess struct {
	scope   Scope
	process *Process
	file    string
}

func IsFileOperation(syscallInfo *SyscallInfo) bool {
	return (syscallInfo.Name == "open") || (syscallInfo.Name == "openat") || (syscallInfo.Name == "access")
}

func (opt fileForProcess) Prompt() (option string, approved string) {
	return "Allow all future access to this file by this process", "All future requests to this file by this process will be APPROVED"
}

func (opt fileForProcess) IsAllowed(scope Scope, process *Process, syscallInfo *SyscallInfo) (isOk bool, approved string) {
	if scope != opt.scope && *process != *opt.process {
		return false, ""
	}

	if IsFileOperation(syscallInfo) && syscallInfo.FilePaths[0] == opt.file {
		return true, "AUTO APPROVED"
	}
	return false, ""
}

func GetSmartOptions(scope Scope, process *Process, syscallInfo *SyscallInfo) []SmartOption {
	options := []SmartOption{}
	if IsFileOperation(syscallInfo) {
		options = append(options, fileForProcess{scope: scope, process: process, file: syscallInfo.FilePaths[0]})
	}
	return options
}
