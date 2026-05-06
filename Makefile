BIN_DIR := bin
BIN := $(BIN_DIR)/aig

.PHONY: build
build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN) ./cmd/aig

.PHONY: test
test:
	go test ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
