#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

GO_BINARY="${GO_BINARY:-}"
DURATION="${DURATION:-10}"

echo "=== Building mihomo-rust (release) ==="
cargo build --release -p mihomo-app -p mihomo-bench

RUST_BINARY="./target/release/mihomo"
BENCH_BINARY="./target/release/mihomo-bench"

# Download Go mihomo if not provided
if [ -z "$GO_BINARY" ]; then
    ARCH=$(uname -m)
    case "$ARCH" in
        arm64|aarch64) GO_ARCH="arm64" ;;
        x86_64)        GO_ARCH="amd64" ;;
        *)             echo "Unsupported arch: $ARCH"; exit 1 ;;
    esac

    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    GO_BINARY="./target/bench/mihomo-go"

    if [ ! -f "$GO_BINARY" ]; then
        echo ""
        echo "=== Downloading Go mihomo ==="
        mkdir -p target/bench

        LATEST=$(gh release view --repo MetaCubeX/mihomo --json tagName -q .tagName)
        echo "Latest Go mihomo release: $LATEST"

        PATTERN="mihomo-${OS}-${GO_ARCH}-${LATEST}.gz"
        echo "Downloading: $PATTERN"

        gh release download "$LATEST" --repo MetaCubeX/mihomo \
            --pattern "$PATTERN" --dir target/bench || {
            echo "Download failed. You can manually download from:"
            echo "  https://github.com/MetaCubeX/mihomo/releases"
            echo "Then run: GO_BINARY=/path/to/mihomo-go bash bench.sh"
            exit 1
        }

        gunzip -f "target/bench/$PATTERN"
        mv "target/bench/mihomo-${OS}-${GO_ARCH}-${LATEST}" "$GO_BINARY"
        chmod +x "$GO_BINARY"
        echo "Go binary: $GO_BINARY"
    else
        echo "Using cached Go binary: $GO_BINARY"
    fi
fi

echo ""
echo "=== Binary sizes ==="
echo "Rust: $(du -h "$RUST_BINARY" | cut -f1)"
echo "Go:   $(du -h "$GO_BINARY" | cut -f1)"

echo ""
echo "=== Running benchmarks ==="
mkdir -p target/bench

"$BENCH_BINARY" \
    --rust-binary "$RUST_BINARY" \
    --go-binary "$GO_BINARY" \
    --config config-bench.yaml \
    --duration "$DURATION" \
    --output target/bench/results.json \
    --markdown

echo ""
echo "Results saved to target/bench/results.json"
