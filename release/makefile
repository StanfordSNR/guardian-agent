GOOS = linux
GOARCH = amd64
VERSION := $(shell git describe --abbrev=4 --dirty --always --tags)

BUILD_FLAGS = -ldflags "-X github.com/StanfordSNR/guardian-agent.Version=$(VERSION)"

BUILD = go build $(BUILD_FLAGS)

OUT_DIR = sga_$(GOOS)_$(GOARCH)

all:
	rm -rf $(OUT_DIR)
	mkdir -p $(OUT_DIR)
	$(BUILD) -o $(OUT_DIR)/sga-guard-bin ../cmd/sga-guard-bin/
	$(BUILD) -o $(OUT_DIR)/sga-stub ../cmd/sga-stub/
	$(BUILD) -o $(OUT_DIR)/sga-ssh ../cmd/sga-ssh/
	cp ../scripts/sga-guard $(OUT_DIR)
	cp ../scripts/sga-env.sh $(OUT_DIR)
	tar czvf sga_$(GOOS)_$(GOARCH).tar.gz $(OUT_DIR)
	