BIN_DIR := bin
BIN := $(BIN_DIR)/aig

# On macOS 14.4+ with Go 1.21, the internal linker omits LC_UUID which causes
# dyld to refuse to launch the binary. Workaround: build with the external
# linker, then re-apply an ad-hoc signature so the kernel accepts it. Drop
# both flags once we move to Go >= 1.22.
LDFLAGS := -linkmode=external

.PHONY: build
build:
	@mkdir -p $(BIN_DIR)
	go build -ldflags="$(LDFLAGS)" -o $(BIN) ./cmd/aig
	@if [ "$$(uname)" = "Darwin" ]; then codesign -s - --force $(BIN); fi

.PHONY: test
test:
	go test ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
