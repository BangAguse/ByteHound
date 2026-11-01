#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"

command -v go >/dev/null 2>&1 || { echo "Go is required (1.22 or newer)." >&2; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "Rust/Cargo is required." >&2; exit 1; }
command -v make >/dev/null 2>&1 || { echo "make is required." >&2; exit 1; }

make build

if [ "$(uname -s)" = "Darwin" ]; then
    LIB="libbytehound_scanner.dylib"
else
    LIB="libbytehound_scanner.so"
fi

if [ -w /usr/local/bin ]; then
    DEST=/usr/local/bin
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    DEST=/usr/local/bin
else
    DEST="${HOME}/.local/bin"
    mkdir -p "$DEST"
    case ":$PATH:" in
        *":$DEST:"*) ;;
        *) echo "Note: add $DEST to PATH to run bytehound from any directory." >&2 ;;
    esac
fi

if [ "$DEST" = "${HOME}/.local/bin" ] || [ -w "$DEST" ]; then
    install -m 0755 "$ROOT/bin/bytehound" "$DEST/bytehound"
    install -m 0644 "$ROOT/bin/$LIB" "$DEST/$LIB"
else
    sudo install -d "$DEST"
    sudo install -m 0755 "$ROOT/bin/bytehound" "$DEST/bytehound"
    sudo install -m 0644 "$ROOT/bin/$LIB" "$DEST/$LIB"
fi

echo "Installed bytehound and $LIB to $DEST"
echo "Run: bytehound --help"
