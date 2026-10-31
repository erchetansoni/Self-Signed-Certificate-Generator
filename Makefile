.PHONY: all build test clean manifest build-windows build-linux

DIST_DIR := dist
TMP_DIR  := .tmp

all: build

$(TMP_DIR):
	mkdir -p $(TMP_DIR)

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

manifest: $(TMP_DIR)
	@echo "==> Compiling Windows PE Resources & Manifest with go-winres..."
	@which go-winres >/dev/null 2>&1 && go-winres make --in winres/winres.json || (\
		go build -o $(TMP_DIR)/winres github.com/tc-hib/go-winres && \
		$(TMP_DIR)/winres make --in winres/winres.json \
	)

build-windows: $(DIST_DIR) manifest
	@echo "==> Building Windows AMD64 binary..."
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o $(DIST_DIR)/certgen-windows-amd64.exe .

build-linux: $(DIST_DIR)
	@echo "==> Building Linux AMD64 binary..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o $(DIST_DIR)/certgen-linux-amd64 .

build: manifest build-windows build-linux
	@echo "==> Build complete. Binaries available in $(DIST_DIR)/"

test: $(TMP_DIR)
	@echo "==> Running test suite..."
	GOTMPDIR=$(CURDIR)/$(TMP_DIR) go test -v -race ./...

clean:
	@echo "==> Cleaning build artifacts..."
	rm -rf $(DIST_DIR) $(TMP_DIR) *.syso

