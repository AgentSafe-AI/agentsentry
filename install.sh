#!/usr/bin/env bash
set -e

echo "🛡️ Installing ToolTrust Scanner..."

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')"
REPO="AgentSafe-AI/tooltrust-scanner"

# Check if a version argument is provided (e.g. v1.0.0), default to latest if not
TARGET_VERSION=${1:-"latest"}

if [ "$TARGET_VERSION" = "latest" ]; then
    echo "🔍 Fetching latest release version..."
    RELEASE_TAG=$(curl -sf "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
else
    echo "🔍 Using specified version: $TARGET_VERSION"
    RELEASE_TAG=$TARGET_VERSION
fi

if [ -z "$RELEASE_TAG" ]; then
    echo "❌ Failed to fetch the latest release."
    exit 1
fi

BINARY_NAME="tooltrust-scanner_${OS}_${ARCH}"
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$RELEASE_TAG/$BINARY_NAME"
CHECKSUM_URL="https://github.com/$REPO/releases/download/$RELEASE_TAG/checksums_${OS}_${ARCH}.txt"

TMP_DIR=$(mktemp -d)
TMP_FILE="$TMP_DIR/tooltrust-scanner"

echo "⬇️ Downloading version $RELEASE_TAG for $OS/$ARCH..."
# Use curl -sfL to fail silently on HTTP errors (like 404) rather than downloading error pages
if ! curl -sfL "$DOWNLOAD_URL" -o "$TMP_FILE"; then
    echo "❌ Failed to download binary. Please check if the version exists for your OS/Arch."
    rm -rf "$TMP_DIR"
    exit 1
fi

echo "🔍 Verifying checksum..."
CHECKSUM_FILE="$TMP_DIR/checksums.txt"
if ! curl -sfL "$CHECKSUM_URL" -o "$CHECKSUM_FILE"; then
    echo "❌ Failed to download checksum file."
    rm -rf "$TMP_DIR"
    exit 1
fi

EXPECTED_CHECKSUM=$(grep "$BINARY_NAME" "$CHECKSUM_FILE" | awk '{print $1}')
if [ -z "$EXPECTED_CHECKSUM" ]; then
    echo "❌ Binary not found in checksum file."
    rm -rf "$TMP_DIR"
    exit 1
fi

if command -v shasum >/dev/null 2>&1; then
    ACTUAL_CHECKSUM=$(shasum -a 256 "$TMP_FILE" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_CHECKSUM=$(sha256sum "$TMP_FILE" | awk '{print $1}')
else
    echo "⚠️  Neither shasum nor sha256sum found. Skipping checksum verification."
    ACTUAL_CHECKSUM=$EXPECTED_CHECKSUM
fi

if [ "$EXPECTED_CHECKSUM" != "$ACTUAL_CHECKSUM" ]; then
    echo "❌ Checksum verification failed!"
    echo "Expected: $EXPECTED_CHECKSUM"
    echo "Actual:   $ACTUAL_CHECKSUM"
    rm -rf "$TMP_DIR"
    exit 1
fi
echo "✅ Checksum verified."

chmod +x "$TMP_FILE"

INSTALL_DIR="/usr/local/bin"
TARGET_FILE="$INSTALL_DIR/tooltrust-scanner"

echo "📦 Installing to $INSTALL_DIR..."
if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP_FILE" "$TARGET_FILE"
else
    echo "⚠️  No write permission for $INSTALL_DIR. Attempting sudo..."
    if sudo -n true 2>/dev/null; then
        sudo mv "$TMP_FILE" "$TARGET_FILE"
    else
        echo "⚠️  Sudo not available or requires password."
        INSTALL_DIR="$HOME/.local/bin"
        TARGET_FILE="$INSTALL_DIR/tooltrust-scanner"
        echo "📦 Falling back to user directory: $INSTALL_DIR..."
        mkdir -p "$INSTALL_DIR"
        mv "$TMP_FILE" "$TARGET_FILE"
        echo "💡 Please ensure $INSTALL_DIR is in your PATH."
    fi
fi

rm -rf "$TMP_DIR"
echo "✅ Installation complete! Run 'tooltrust-scanner --help' to get started."
