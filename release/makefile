GOOS = linux
GOARCH = amd64

all:
	mkdir -p sga_$(GOOS)_$(GOARCH)
	go build -o sga_$(GOOS)_$(GOARCH)/sga-guard-bin ../cmd/sga-guard-bin/
	go build -o sga_$(GOOS)_$(GOARCH)/sga-stub ../cmd/sga-stub/
	go build -o sga_$(GOOS)_$(GOARCH)/sga-run ../cmd/sga-run/
	cp ../scripts/sga-guard sga_$(GOOS)_$(GOARCH)/sga-guard
	tar czvf sga_$(GOOS)_$(GOARCH).tar.gz sga_$(GOOS)_$(GOARCH)
	