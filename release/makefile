GOOS = linux
GOARCH = amd64

all:
	mkdir -p guardian-agent_$(GOOS)_$(GOARCH)
	go build -o guardian-agent_$(GOOS)_$(GOARCH)/ssh-guard-agent ../cmd/ssh-guard-agent/
	go build -o guardian-agent_$(GOOS)_$(GOARCH)/ssh-fwd-stub ../cmd/ssh-fwd-stub/
	tar czvf guardian-agent_$(GOOS)_$(GOARCH).tar.gz guardian-agent_$(GOOS)_$(GOARCH)
	