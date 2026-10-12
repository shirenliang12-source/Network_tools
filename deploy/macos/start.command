#!/bin/bash
set -e
cd "$(dirname "$0")"

case "$(uname -m)" in
  arm64) BIN="netops-console-macos-arm64" ;;
  x86_64) BIN="netops-console-macos-x64" ;;
  *) echo "不支持的处理器架构：$(uname -m)"; read -r; exit 1 ;;
esac

chmod +x "$BIN"
xattr -d com.apple.quarantine "$BIN" 2>/dev/null || true
./"$BIN"
