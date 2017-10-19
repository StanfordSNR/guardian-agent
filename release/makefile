GOOS = linux
GOARCH = amd64

all:
	rm -rf sga_$(GOOS)_$(GOARCH)
	mkdir -p sga_$(GOOS)_$(GOARCH)
	go build -o sga_$(GOOS)_$(GOARCH)/sga-guard-bin ../cmd/sga-guard-bin/
	go build -o sga_$(GOOS)_$(GOARCH)/sga-stub ../cmd/sga-stub/
	go build -o sga_$(GOOS)_$(GOARCH)/sga-ssh ../cmd/sga-ssh/
	cp ../scripts/sga-guard sga_$(GOOS)_$(GOARCH)/
	cp ../scripts/sga-env.sh sga_$(GOOS)_$(GOARCH)/
	tar czvf sga_$(GOOS)_$(GOARCH).tar.gz sga_$(GOOS)_$(GOARCH)
	