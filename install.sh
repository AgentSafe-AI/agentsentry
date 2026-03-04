#!/usr/bin/env bash
set -e

echo "🛡️ Installing ToolTrust Scanner..."

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')"
REPO="AgentSafe-AI/tooltrust-scanner"

# 檢查是否有傳入參數（例如 v1.0.0），沒有的話預設為 latest
TARGET_VERSION=${1:-"latest"}

if [ "$TARGET_VERSION" = "latest" ]; then
    echo "🔍 Fetching latest release version..."
    RELEASE_TAG=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
else
    echo "🔍 Using specified version: $TARGET_VERSION"
    RELEASE_TAG=$TARGET_VERSION
fi

if [ -z "$RELEASE_TAG" ]; then
    echo "❌ Failed to fetch the latest release."
    exit 1
fi

# 組合下載網址
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$RELEASE_TAG/tooltrust_${OS}_${ARCH}"
TMP_DIR=$(mktemp -d)
TMP_FILE="$TMP_DIR/tooltrust"

echo "⬇️ Downloading version $RELEASE_TAG for $OS/$ARCH..."
curl -sL "$DOWNLOAD_URL" -o "$TMP_FILE"
chmod +x "$TMP_FILE"

echo "📦 Moving to /usr/local/bin/tooltrust (requires sudo)..."
sudo mv "$TMP_FILE" /usr/local/bin/tooltrust
rm -rf "$TMP_DIR"

echo "✅ Installation complete! Run 'tooltrust --help' to get started."
