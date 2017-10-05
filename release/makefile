GOOS = linux
GOARCH = amd64

all:
	mkdir -p guardian-agent_$(GOOS)_$(GOARCH)
	go build -o guardian-agent_$(GOOS)_$(GOARCH)/sga-guard ../cmd/sga-guard/
	go build -o guardian-agent_$(GOOS)_$(GOARCH)/sga-stub ../cmd/sga-stub/
		go build -o guardian-agent_$(GOOS)_$(GOARCH)/sga-run ../cmd/sga-run/
	tar czvf guardian-agent_$(GOOS)_$(GOARCH).tar.gz guardian-agent_$(GOOS)_$(GOARCH)
	