#!/usr/bin/env bash
set -euo pipefail

# Generate Tauri app icons from a source PNG (1024x1024 recommended).
# Requires: sips (macOS) or ImageMagick (Linux/Windows)
#
# Usage: ./generate-icons.sh <source-image.png>

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ICONS_DIR="$SCRIPT_DIR/../icons"
SOURCE="${1:-}"

if [ -z "$SOURCE" ]; then
    echo "Usage: $0 <source-image.png>"
    echo "  Source should be a 1024x1024 PNG with transparency."
    exit 1
fi

if [ ! -f "$SOURCE" ]; then
    echo "Error: File not found: $SOURCE"
    exit 1
fi

echo "🎨 Generating Tauri icons from: $SOURCE"

mkdir -p "$ICONS_DIR"

if command -v sips &>/dev/null; then
    # macOS — use sips
    sips -z 32 32 "$SOURCE" --out "$ICONS_DIR/32x32.png"
    sips -z 128 128 "$SOURCE" --out "$ICONS_DIR/128x128.png"
    sips -z 256 256 "$SOURCE" --out "$ICONS_DIR/128x128@2x.png"
    sips -z 64 64 "$SOURCE" --out "$ICONS_DIR/tray-icon.png"
    sips -z 64 64 "$SOURCE" --out "$ICONS_DIR/tray-idle.png"
    sips -z 64 64 "$SOURCE" --out "$ICONS_DIR/tray-scanning.png"
    sips -z 64 64 "$SOURCE" --out "$ICONS_DIR/tray-critical.png"
    sips -z 64 64 "$SOURCE" --out "$ICONS_DIR/tray-error.png"

    # Generate .icns for macOS
    ICONSET_DIR=$(mktemp -d)/icon.iconset
    mkdir -p "$ICONSET_DIR"
    sips -z 16 16 "$SOURCE" --out "$ICONSET_DIR/icon_16x16.png"
    sips -z 32 32 "$SOURCE" --out "$ICONSET_DIR/icon_16x16@2x.png"
    sips -z 32 32 "$SOURCE" --out "$ICONSET_DIR/icon_32x32.png"
    sips -z 64 64 "$SOURCE" --out "$ICONSET_DIR/icon_32x32@2x.png"
    sips -z 128 128 "$SOURCE" --out "$ICONSET_DIR/icon_128x128.png"
    sips -z 256 256 "$SOURCE" --out "$ICONSET_DIR/icon_128x128@2x.png"
    sips -z 256 256 "$SOURCE" --out "$ICONSET_DIR/icon_256x256.png"
    sips -z 512 512 "$SOURCE" --out "$ICONSET_DIR/icon_256x256@2x.png"
    sips -z 512 512 "$SOURCE" --out "$ICONSET_DIR/icon_512x512.png"
    sips -z 1024 1024 "$SOURCE" --out "$ICONSET_DIR/icon_512x512@2x.png"
    iconutil -c icns "$ICONSET_DIR" -o "$ICONS_DIR/icon.icns"
    rm -rf "$(dirname "$ICONSET_DIR")"

    echo "  ✅ macOS .icns generated"

elif command -v convert &>/dev/null; then
    # Linux/Windows — use ImageMagick
    convert "$SOURCE" -resize 32x32 "$ICONS_DIR/32x32.png"
    convert "$SOURCE" -resize 128x128 "$ICONS_DIR/128x128.png"
    convert "$SOURCE" -resize 256x256 "$ICONS_DIR/128x128@2x.png"
    convert "$SOURCE" -resize 64x64 "$ICONS_DIR/tray-icon.png"
    convert "$SOURCE" -resize 64x64 "$ICONS_DIR/tray-idle.png"
    convert "$SOURCE" -resize 64x64 "$ICONS_DIR/tray-scanning.png"
    convert "$SOURCE" -resize 64x64 "$ICONS_DIR/tray-critical.png"
    convert "$SOURCE" -resize 64x64 "$ICONS_DIR/tray-error.png"

    # Generate .ico for Windows
    convert "$SOURCE" -resize 256x256 -define icon:auto-resize=256,128,64,48,32,16 "$ICONS_DIR/icon.ico"

    echo "  ✅ Icons generated with ImageMagick"
else
    echo "Error: Neither sips (macOS) nor ImageMagick (convert) found."
    echo "Install ImageMagick: sudo apt-get install imagemagick"
    exit 1
fi

echo ""
echo "Generated icons in: $ICONS_DIR"
ls -la "$ICONS_DIR"
