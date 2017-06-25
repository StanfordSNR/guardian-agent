GOOS = linux
GOARCH = amd64

all:
	mkdir -p sshguard_$(GOOS)_$(GOARCH)
	go build -o sshguard_$(GOOS)_$(GOARCH)/sshguard ../sshguard/
	go build -o sshguard_$(GOOS)_$(GOARCH)/sshfwdstub ../sshfwdstub/
	tar czvf sshguard_$(GOOS)_$(GOARCH).tar.gz sshguard_$(GOOS)_$(GOARCH)
	