#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DIST="$ROOT/dist"
APP="$DIST/Library.app"
APP_VERSION="$(tr -d '\r\n' < "$ROOT/VERSION")"
if ! printf '%s\n' "$APP_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
	echo "Invalid VERSION: $APP_VERSION (expected MAJOR.MINOR.PATCH)" >&2
	exit 1
fi
TEMP_BUILD="$(mktemp -d "${TMPDIR:-/tmp}/library-build.XXXXXX")"
ICONSET="$TEMP_BUILD/AppIcon.iconset"
trap 'rm -rf "$TEMP_BUILD"' EXIT HUP INT TERM

mkdir -p "$DIST" "$ICONSET" "$APP/Contents/MacOS" "$APP/Contents/Helpers" "$APP/Contents/Resources"
cp "$ROOT/internal/ui/operations.json" "$APP/Contents/Resources/operations.json"

for SPEC in "icp4 16" "icp5 32" "icp6 64" "ic07 128" "ic08 256" "ic09 512" "ic10 1024"; do
	set -- $SPEC
	/usr/bin/sips -z "$2" "$2" "$ROOT/assets/app-icon.png" --out "$ICONSET/$1.png" >/dev/null
done
python3 - "$ICONSET" "$APP/Contents/Resources/AppIcon.icns" <<'PYTHON'
import pathlib
import struct
import sys

iconset = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
chunks = []
for icon_type in ("icp4", "icp5", "icp6", "ic07", "ic08", "ic09", "ic10"):
    data = (iconset / f"{icon_type}.png").read_bytes()
    chunks.append(icon_type.encode("ascii") + struct.pack(">I", len(data) + 8) + data)
payload = b"".join(chunks)
output.write_bytes(b"icns" + struct.pack(">I", len(payload) + 8) + payload)
PYTHON

GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -trimpath -ldflags="-s -w -X photovault/internal/buildinfo.Version=$APP_VERSION" -o "$TEMP_BUILD/Library-arm64" "$ROOT"
GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build -trimpath -ldflags="-s -w -X photovault/internal/buildinfo.Version=$APP_VERSION" -o "$TEMP_BUILD/Library-amd64" "$ROOT"
/usr/bin/lipo -create "$TEMP_BUILD/Library-arm64" "$TEMP_BUILD/Library-amd64" -output "$APP/Contents/MacOS/Library"
chmod 755 "$APP/Contents/MacOS/Library"

for ARCH in arm64 x86_64; do
	/usr/bin/clang -arch "$ARCH" -mmacosx-version-min=11.0 -fobjc-arc \
		"$ROOT/scripts/media-viewer.m" -framework AppKit -framework AVKit -framework AVFoundation -framework PDFKit -framework QuickLookUI \
		-framework ImageIO -framework CoreServices \
		-o "$TEMP_BUILD/LibraryMediaViewer-$ARCH"
done
/usr/bin/lipo -create "$TEMP_BUILD/LibraryMediaViewer-arm64" "$TEMP_BUILD/LibraryMediaViewer-x86_64" \
	-output "$APP/Contents/Helpers/LibraryMediaViewer"
chmod 755 "$APP/Contents/Helpers/LibraryMediaViewer"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key><string>en</string>
	<key>CFBundleExecutable</key><string>Library</string>
	<key>CFBundleIconFile</key><string>AppIcon</string>
	<key>CFBundleIdentifier</key><string>com.library.viewer</string>
	<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
	<key>CFBundleName</key><string>Library</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleShortVersionString</key><string>$APP_VERSION</string>
	<key>CFBundleVersion</key><string>$APP_VERSION</string>
	<key>LSApplicationCategoryType</key><string>public.app-category.productivity</string>
	<key>LSMinimumSystemVersion</key><string>11.0</string>
	<key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

SIGNING_IDENTITY="${LIBRARY_CODESIGN_IDENTITY:--}"
/usr/bin/codesign --force --sign "$SIGNING_IDENTITY" --identifier com.library.viewer.helper \
	"$APP/Contents/Helpers/LibraryMediaViewer"
/usr/bin/codesign --force --sign "$SIGNING_IDENTITY" "$APP"
/usr/bin/codesign --verify --deep --strict "$APP"

rm -rf "$DIST/Console.app"
rm -f "$DIST/photovault-desktop"
echo "Built $APP (universal arm64 + x86_64; signing identity: $SIGNING_IDENTITY)"
