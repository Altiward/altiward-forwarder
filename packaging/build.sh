#!/bin/bash
# Builds Altiward Forwarder.app around altiward-forwarder-hook (universal, signed), the
# Privileges profile pinned to it, and Altiward-Forwarder-<version>.pkg.
#
#   packaging/build.sh            (or: make hook)
#
# Environment (all optional; the defaults give a local, ad-hoc-signed build):
#   VERSION              the hook's version (default 0.0.0-dev); the release sets it from the tag
#   OUT                  output folder (default ~/Library/Caches/altiward-forwarder/package;
#                        never inside iCloud-synced ~/Documents, where codesign refuses products)
#   APP_IDENTITY         codesign identity (default "-", ad hoc)
#   INSTALLER_IDENTITY   productbuild signing identity ("Developer ID Installer: …")
#   KEYCHAIN             keychain holding those identities
#   NOTARY_KEY_PATH, NOTARY_KEY_ID, NOTARY_ISSUER
#                        App Store Connect API key: when set, notarize and staple the package
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
VERSION="${VERSION:-0.0.0-dev}"
OUT="${OUT:-$HOME/Library/Caches/altiward-forwarder/package}"
APP_IDENTITY="${APP_IDENTITY:--}"
INSTALL_DIR="/Library/Application Support/Altiward Forwarder"
BIN_NAME=altiward-forwarder-hook
APP_NAME="Altiward Forwarder"
AGENT_LABEL=com.altiward.forwarder.flush

case "$OUT" in "$HOME/Documents"*|"$HOME/Library/Mobile Documents"*)
  echo "OUT must be outside iCloud-synced folders: $OUT" >&2; exit 1;; esac

echo "== building $VERSION (arm64 and x86_64)"
rm -rf "$OUT" && mkdir -p "$OUT/arch"
for arch in arm64 amd64; do
  (cd "$REPO" && CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X main.version=$VERSION" -o "$OUT/arch/$BIN_NAME-$arch" ./cmd/altiward-forwarder-hook)
done

# The hook lives in an app bundle so macOS can name it "Altiward Forwarder", with the
# Altiward icon, in Login Items and anywhere else it lists the LaunchAgent.
echo "== assembling $APP_NAME.app"
APP="$OUT/$APP_NAME.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
# The executable is named for what Privileges shows under "Run after privilege change", as
# the Altiward agent's hook is; altiward-forwarder-hook links to it for running it by hand.
lipo -create -output "$APP/Contents/MacOS/$APP_NAME" "$OUT/arch/$BIN_NAME-arm64" "$OUT/arch/$BIN_NAME-amd64"
ln -s "$APP_NAME" "$APP/Contents/MacOS/$BIN_NAME"
rm -rf "$OUT/arch"
cp "$HERE/AppIcon.icns" "$APP/Contents/Resources/"
cp "$REPO/LICENSE" "$REPO/NOTICE" "$APP/Contents/Resources/"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>com.altiward.forwarder.hook</string>
    <key>CFBundleName</key><string>$APP_NAME</string>
    <key>CFBundleDisplayName</key><string>$APP_NAME</string>
    <key>CFBundleExecutable</key><string>$APP_NAME</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>LSUIElement</key><true/>
    <key>NSHumanReadableCopyright</key><string>Works with SAP Privileges.</string>
</dict>
</plist>
PLIST

echo "== signing ($([ "$APP_IDENTITY" = "-" ] && echo "ad hoc" || echo "$APP_IDENTITY"))"
# Signing the bundle signs its executable as com.altiward.forwarder.hook (the bundle's ID).
SIGN=(codesign --force --options runtime)
if [ "$APP_IDENTITY" = "-" ]; then SIGN+=(--timestamp=none); else SIGN+=(--timestamp); fi
[ -n "${KEYCHAIN:-}" ] && SIGN+=(--keychain "$KEYCHAIN")
"${SIGN[@]}" --sign "$APP_IDENTITY" "$APP"
codesign --verify --strict "$APP"

echo "== profiles"
HOOK_SHA="$(shasum -a 256 "$APP/Contents/MacOS/$APP_NAME" | cut -d' ' -f1)"
# Privileges runs the hook only if its SHA-256 matches, so the profile is pinned to this build.
sed "s/REPLACE_WITH_SHA256_OF_SIGNED_HOOK/$HOOK_SHA/" "$REPO/profiles/altiward-forwarder-privileges-hook.mobileconfig" > "$OUT/altiward-forwarder-privileges-hook.mobileconfig"
cp "$REPO/profiles/altiward-forwarder-hook-settings.mobileconfig" "$REPO/profiles/altiward-forwarder-login-items.mobileconfig" "$OUT/"
plutil -lint "$OUT"/*.mobileconfig >/dev/null

echo "== packaging"
ROOT="$OUT/pkgroot"
mkdir -p "$ROOT$INSTALL_DIR" "$ROOT/Library/LaunchAgents"
ditto "$APP" "$ROOT$INSTALL_DIR/$APP_NAME.app"
install -m 0755 "$REPO/scripts/uninstall.sh" "$ROOT$INSTALL_DIR/uninstall.sh"
install -m 0644 "$HERE/LaunchAgents/$AGENT_LABEL.plist" "$ROOT/Library/LaunchAgents/$AGENT_LABEL.plist"
# --ownership recommended installs everything as root:wheel.
pkgbuild --root "$ROOT" --scripts "$HERE/scripts" --ownership recommended \
  --identifier com.altiward.forwarder.pkg --version "$VERSION" --install-location / "$OUT/component.pkg" >/dev/null
PKG="$OUT/Altiward-Forwarder-$VERSION.pkg"
productbuild --synthesize --package "$OUT/component.pkg" "$OUT/distribution.xml" >/dev/null
awk '{ print } /<installer-gui-script/ {
  print "    <title>Altiward Forwarder</title>"
  print "    <domains enable_anywhere=\"false\" enable_currentUserHome=\"false\" enable_localSystem=\"true\"/>"
  print "    <allowed-os-versions><os-version min=\"13.0\"/></allowed-os-versions>"
}' "$OUT/distribution.xml" > "$OUT/distribution.tmp" && mv "$OUT/distribution.tmp" "$OUT/distribution.xml"
PB=(productbuild --distribution "$OUT/distribution.xml" --package-path "$OUT")
if [ -n "${INSTALLER_IDENTITY:-}" ]; then
  PB+=(--sign "$INSTALLER_IDENTITY"); [ -n "${KEYCHAIN:-}" ] && PB+=(--keychain "$KEYCHAIN")
fi
"${PB[@]}" "$PKG" >/dev/null
rm -rf "$ROOT" "$OUT/component.pkg" "$OUT/distribution.xml"

if [ -n "${NOTARY_KEY_PATH:-}" ]; then
  echo "== notarizing"
  xcrun notarytool submit "$PKG" --key "$NOTARY_KEY_PATH" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER" --wait
  xcrun stapler staple "$PKG"
fi

echo "== done"
echo "  $PKG"
echo "  $OUT/altiward-forwarder-privileges-hook.mobileconfig (PostChangeExecutableChecksum $HOOK_SHA)"
echo "  $OUT/altiward-forwarder-hook-settings.mobileconfig (fill in a destination)"
echo "  $OUT/altiward-forwarder-login-items.mobileconfig (deploy through MDM)"
