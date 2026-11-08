VERSION ?= 0.2.0
NFPM_VERSION ?= v2.36.1
GO ?= go
export GOTOOLCHAIN := local

# Go 1.22's internal linker produces Mach-O binaries without LC_UUID, which
# current macOS refuses to run; link host binaries (tests, nfpm) externally there.
ifeq ($(shell uname -s),Darwin)
HOST_LDFLAGS := -ldflags=-linkmode=external
endif

DEB := dist/typo-guard_$(VERSION)_amd64.deb

.PHONY: all test vet build deb clean

all: test deb

vet:
	$(GO) vet ./...

test: vet
	$(GO) test $(HOST_LDFLAGS) ./...

build:
	mkdir -p build
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath \
		-ldflags "-s -w -X main.version=$(VERSION)" -o build/typo-guard .

deb: build
	mkdir -p dist
	rm -f $(DEB)
	VERSION=$(VERSION) $(GO) run $(HOST_LDFLAGS) github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VERSION) \
		package -f packaging/nfpm.yaml -p deb -t $(DEB)

clean:
	rm -rf build dist
