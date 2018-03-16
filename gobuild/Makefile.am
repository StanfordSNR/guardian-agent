go_bins:
	CGO_LDFLAGS="-L$(realpath $(top_builddir))/proto" go install github.com/StanfordSNR/guardian-agent/...

.PHONY: go_bins

all: go_bins