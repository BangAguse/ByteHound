GO ?= go
CARGO ?= cargo
BUILD_DIR := bin

.PHONY: build test clean

build:
	$(CARGO) build --manifest-path scanner/Cargo.toml --release
	mkdir -p $(BUILD_DIR)
ifeq ($(OS),Windows_NT)
	copy scanner\target\release\bytehound_scanner.dll $(BUILD_DIR)\bytehound_scanner.dll
	$(GO) build -o $(BUILD_DIR)\bytehound.exe .
else
	@if [ "$$(uname -s)" = "Darwin" ]; then \
		cp scanner/target/release/libbytehound_scanner.dylib $(BUILD_DIR)/libbytehound_scanner.dylib; \
	else \
		cp scanner/target/release/libbytehound_scanner.so $(BUILD_DIR)/libbytehound_scanner.so; \
	fi
	$(GO) build -o $(BUILD_DIR)/bytehound .
endif

test:
	$(CARGO) test --manifest-path scanner/Cargo.toml
	$(CARGO) build --manifest-path scanner/Cargo.toml --release
	$(GO) test ./...

clean:
	$(CARGO) clean --manifest-path scanner/Cargo.toml
	rm -rf $(BUILD_DIR)
