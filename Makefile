# Makefile for gnark-stwo verifier
#
# This builds both the Rust FFI library and the Go verifier binary.

.PHONY: all build-rust build-go test clean install-rust-toolchain help

# Default target
all: build-rust build-go

# Rust library paths
RUST_DIR := rust
RUST_TARGET := $(RUST_DIR)/target/release
RUST_LIB := $(RUST_TARGET)/libstwo_gnark.so

# Go binary
GO_BINARY := stwo-verifier

# Help target
help:
	@echo "gnark-stwo verifier build system"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all                  Build both Rust library and Go binary (default)"
	@echo "  build-rust           Build the Rust FFI library"
	@echo "  build-go             Build the Go verifier binary"
	@echo "  test                 Run integration test"
	@echo "  test-unit            Run Go unit tests"
	@echo "  clean                Clean all build artifacts"
	@echo "  install-rust-toolchain  Install required Rust nightly toolchain"
	@echo ""

# Install the required Rust toolchain
install-rust-toolchain:
	@echo "Installing required Rust nightly toolchain..."
	rustup install nightly-2025-07-14
	cd $(RUST_DIR) && rustup override set nightly-2025-07-14
	@echo "Rust toolchain installed successfully"

# Build the Rust FFI library
build-rust:
	@echo "Building Rust FFI library..."
	cd $(RUST_DIR) && cargo build --release --features stwo_support
	@echo "Rust library built: $(RUST_LIB)"

# Build the Go binary
build-go: $(RUST_LIB)
	@echo "Building Go verifier binary..."
	CGO_ENABLED=1 \
	CGO_LDFLAGS="-L$(shell pwd)/$(RUST_TARGET) -lstwo_gnark -ldl -lpthread -lm" \
	go build -o $(GO_BINARY) ./cmd
	@echo "Go binary built: $(GO_BINARY)"

# Ensure Rust library exists
$(RUST_LIB): build-rust

# Run integration test (example + build + keygen + prove + verify)
test: $(GO_BINARY)
	@echo "=== Integration Test ==="
	@echo ""
	@echo "Step 1: Generate example witness via SDK..."
	LD_LIBRARY_PATH=$(shell pwd)/$(RUST_TARGET) ./$(GO_BINARY) example \
		--name fibonacci \
		--output ./witness.json
	@echo ""
	@echo "Step 2: Build circuit..."
	LD_LIBRARY_PATH=$(shell pwd)/$(RUST_TARGET) ./$(GO_BINARY) build \
		--witness ./witness.json \
		--output ./circuit.r1cs
	@echo ""
	@echo "Step 3: Generate keys..."
	LD_LIBRARY_PATH=$(shell pwd)/$(RUST_TARGET) ./$(GO_BINARY) keygen \
		--circuit ./circuit.r1cs \
		--pk ./proving.key \
		--vk ./verifying.key
	@echo ""
	@echo "Step 4: Generate Groth16 proof..."
	LD_LIBRARY_PATH=$(shell pwd)/$(RUST_TARGET) ./$(GO_BINARY) prove \
		--witness ./witness.json \
		--circuit ./circuit.r1cs \
		--pk ./proving.key \
		--output ./proof.bin \
		--public-output ./public_witness.bin
	@echo ""
	@echo "Step 5: Verify proof..."
	LD_LIBRARY_PATH=$(shell pwd)/$(RUST_TARGET) ./$(GO_BINARY) verify \
		--proof ./proof.bin \
		--vk ./verifying.key \
		--public ./public_witness.bin
	@echo ""
	@echo "=== All tests passed! ==="

# Run Go unit tests
test-unit:
	@echo "Running Go unit tests..."
	go test -v ./...

# Clean all build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cd $(RUST_DIR) && cargo clean
	rm -f $(GO_BINARY)
	rm -f ./witness.json ./circuit.r1cs ./proving.key ./verifying.key ./proof.bin ./public_witness.bin
	@echo "Clean complete"

# Show CLI help
version: $(GO_BINARY)
	./$(GO_BINARY) help
