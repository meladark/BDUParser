.PHONY: build build_env test clean all \
	ffi-build ffi-build-macos-arm64 ffi-build-linux-amd64 ffi-build-all \
	ffi-go-test ffi-test ffi-tools ffi-package \
	docker-test-image docker-test docker-test-latex help

NATIVE_RUST_TARGET := aarch64-apple-darwin
LINUX_AMD64_RUST_TARGET := x86_64-unknown-linux-gnu
FFI_MANIFEST := ffi/Cargo.toml
FFI_GO_DIR := ffi/go
FFI_DIST_DIR := dist/ffi
ZIGBUILD_BIN := $(shell if command -v cargo-zigbuild >/dev/null 2>&1; then command -v cargo-zigbuild; elif [ -x "$$HOME/.cargo/bin/cargo-zigbuild" ]; then printf "%s" "$$HOME/.cargo/bin/cargo-zigbuild"; fi)
RUSTUP_TOOLCHAIN := $(shell rustup show active-toolchain | cut -d' ' -f1)
RUSTUP_RUN := rustup run $(RUSTUP_TOOLCHAIN)
RUSTUP_RUSTC := $(shell rustup which rustc --toolchain $(RUSTUP_TOOLCHAIN))
DOCKER_TEST_IMAGE := bdu-parser-test:debian-latest
DOCKER_TEST_DB_URL := postgresql://bdu:bdu@host.docker.internal:5438/bdu

build_env:
	docker-compose up -d 

build:
	echo "Build BDU parser"
	cargo build --release

ffi-build: ffi-build-macos-arm64

ffi-build-macos-arm64:
	echo "Build FFI cdylib for macOS arm64"
	cargo build --manifest-path $(FFI_MANIFEST) --release

ffi-build-linux-amd64:
	@if [ -n "$(ZIGBUILD_BIN)" ] && command -v zig >/dev/null 2>&1; then \
		echo "Build FFI cdylib for Linux amd64 with cargo-zigbuild"; \
		RUSTC="$(RUSTUP_RUSTC)" $(RUSTUP_RUN) cargo zigbuild --manifest-path $(FFI_MANIFEST) --release --target $(LINUX_AMD64_RUST_TARGET); \
	elif command -v x86_64-linux-gnu-gcc >/dev/null 2>&1; then \
		echo "Build FFI cdylib for Linux amd64 with GNU cross-linker"; \
		CARGO_TARGET_$(shell echo $(LINUX_AMD64_RUST_TARGET) | tr a-z- A-Z_)_LINKER=x86_64-linux-gnu-gcc \
			$(RUSTUP_RUN) cargo build --manifest-path $(FFI_MANIFEST) --release --target $(LINUX_AMD64_RUST_TARGET); \
	else \
		echo "Missing Linux amd64 cross-build toolchain."; \
		echo "Recommended on macOS:"; \
		echo "  brew install zig"; \
		echo "  cargo install cargo-zigbuild"; \
		echo "  rustup target add $(LINUX_AMD64_RUST_TARGET) --toolchain $(RUSTUP_TOOLCHAIN)"; \
		echo "Alternative: install x86_64-linux-gnu-gcc and rerun this target."; \
		exit 1; \
	fi

ffi-build-all: ffi-build-macos-arm64 ffi-build-linux-amd64

ffi-go-test: ffi-build-macos-arm64
	echo "Run Go tests for FFI"
	cd $(FFI_GO_DIR) && go test ./... -v

ffi-test: ffi-go-test

ffi-tools:
	@printf "%s\n" \
		"Recommended macOS setup for Linux amd64 cross-build:" \
		"  brew install zig" \
		"  cargo install cargo-zigbuild" \
		"  rustup target add $(LINUX_AMD64_RUST_TARGET) --toolchain $(RUSTUP_TOOLCHAIN)"

ffi-package: ffi-build-macos-arm64 ffi-build-linux-amd64
	echo "Package FFI artifacts into $(FFI_DIST_DIR)"
	mkdir -p "$(FFI_DIST_DIR)/macos-arm64" "$(FFI_DIST_DIR)/linux-amd64"
	cp "ffi/bdu_parser_ffi.h" "$(FFI_DIST_DIR)/"
	cp "ffi/target/release/libbdu_parser_ffi.dylib" "$(FFI_DIST_DIR)/macos-arm64/"
	cp "ffi/target/x86_64-unknown-linux-gnu/release/libbdu_parser_ffi.so" "$(FFI_DIST_DIR)/linux-amd64/"

test: build
	echo "Run tests"
	docker-compose up -d
	RUST_LOG=debug cargo test test_postgres --verbose
	RUST_LOG=debug cargo test --package bdu_parser --lib -- tests
	docker-compose stop

docker-test-image:
	echo "Build Debian test image"
	docker build -f Dockerfile.test -t $(DOCKER_TEST_IMAGE) .

docker-test: docker-test-image
	echo "Run tests in Debian container"
	docker-compose up -d
	docker run --rm \
		--add-host=host.docker.internal:host-gateway \
		-e BDU_TEST_DATABASE_URL=$(DOCKER_TEST_DB_URL) \
		-v "$(CURDIR):/workspace" \
		-w /workspace \
		$(DOCKER_TEST_IMAGE) \
		/bin/sh -lc 'cargo test --package bdu_parser --lib -- --nocapture'
	docker-compose stop

docker-test-latex: docker-test-image
	echo "Run test_latex in Debian container"
	docker-compose up -d
	docker run --rm \
		--add-host=host.docker.internal:host-gateway \
		-e BDU_TEST_DATABASE_URL=$(DOCKER_TEST_DB_URL) \
		-v "$(CURDIR):/workspace" \
		-w /workspace \
		$(DOCKER_TEST_IMAGE) \
		/bin/sh -lc 'cargo test test_latex -- --nocapture'
	docker-compose stop

clean:
	cargo clean
	docker-compose stop
	docker-compose rm 

all: build test

help:
	@printf "%s\n" \
		"build                 Build the main Rust crate" \
		"test                  Run Rust tests" \
		"ffi-build             Build FFI cdylib for native macOS arm64" \
		"ffi-build-macos-arm64 Build FFI cdylib for macOS arm64" \
		"ffi-build-linux-amd64 Build FFI cdylib for Linux amd64" \
		"ffi-build-all         Build FFI cdylib for both configured targets" \
		"ffi-go-test           Build native FFI cdylib and run Go tests" \
		"ffi-test              Alias for ffi-go-test" \
		"ffi-tools             Show recommended cross-build tool setup" \
		"ffi-package           Build and copy FFI artifacts into dist/ffi" \
		"docker-test-image     Build Debian-based Docker image for test runs" \
		"docker-test           Run Rust tests inside the Debian test image" \
		"docker-test-latex     Run only test_latex inside the Debian test image"
