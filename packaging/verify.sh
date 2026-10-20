#!/bin/bash
# Checks a build from build.sh: the binary's architectures, signature and version, the
# profiles, the package payload, and postinstall against a scratch volume (nothing is
# installed and launchd isn't touched).
#
#   packaging/verify.sh [OUT_DIR]        default ~/Library/Caches/altiward-forwarder/package
#   RELEASE=1 also requires Developer ID signatures, notarization and stapling.
set -euo pipefail

OUT="${1:-$HOME/Library/Caches/altiward-forwarder/package}"
APP="$OUT/Altiward Forwarder.app"
# The executable is named for what Privileges shows under "Run after privilege change";
# altiward-forwarder-hook is a link to it for running it by hand.
BIN="$APP/Contents/MacOS/Altiward Forwarder"
CLI="$APP/Contents/MacOS/altiward-forwarder-hook"
INSTALL_DIR="/Library/Application Support/Altiward Forwarder"
INSTALLED_BIN="$INSTALL_DIR/Altiward Forwarder.app/Contents/MacOS/Altiward Forwarder"
AGENT_LABEL=com.altiward.forwarder.flush
failures=0
check() { # description, command...
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "ok   $what"; else echo "FAIL $what"; failures=$((failures + 1)); fi
}
plist() { [ -f "$1" ] && /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null; }

VERSION="$("$BIN" --version 2>/dev/null || true)"
PKG="$OUT/Altiward-Forwarder-$VERSION.pkg"

check "binary exists and reports a version" test -n "$VERSION"
check "binary is universal (arm64 and x86_64)" bash -c 'lipo -archs "$1" | grep -q arm64 && lipo -archs "$1" | grep -q x86_64' _ "$BIN"
check "signed as com.altiward.forwarder.hook" bash -c 'codesign -d --verbose=2 "$1" 2>&1 | grep -q "^Identifier=com.altiward.forwarder.hook$"' _ "$BIN"
check "hardened runtime" bash -c 'codesign -d --verbose=2 "$1" 2>&1 | grep -q "flags=.*runtime"' _ "$BIN"
check "signature verifies (strict)" codesign --verify --strict "$BIN"
check "bundle signature verifies (strict)" codesign --verify --strict "$APP"
check "bundle is com.altiward.forwarder.hook, named Altiward Forwarder" bash -c 'test "$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$1/Contents/Info.plist")" = com.altiward.forwarder.hook && test "$(/usr/libexec/PlistBuddy -c "Print :CFBundleName" "$1/Contents/Info.plist")" = "Altiward Forwarder"' _ "$APP"
check "bundle has the Altiward icon" bash -c 'test "$(/usr/libexec/PlistBuddy -c "Print :CFBundleIconFile" "$1/Contents/Info.plist")" = AppIcon && test -s "$1/Contents/Resources/AppIcon.icns"' _ "$APP"
check "altiward-forwarder-hook links to the executable" bash -c 'test -L "$1" && test "$(readlink "$1")" = "Altiward Forwarder"' _ "$CLI"
check "bundle carries LICENSE and NOTICE" test -s "$APP/Contents/Resources/LICENSE" -a -s "$APP/Contents/Resources/NOTICE"
check "login items profile is valid and names the LaunchAgent" bash -c 'plutil -lint "$1" && grep -q "<string>com.altiward.forwarder.flush</string>" "$1"' _ "$OUT/altiward-forwarder-login-items.mobileconfig"
if [ -e "/Library/Managed Preferences/com.altiward.forwarder.plist" ]; then
  echo "skip --test check: this Mac has hook settings, so --test would send an event"
else
  check "--test without settings exits 1 and sends nothing" bash -c 'out=$(HOME=$(mktemp -d) "$1" --test 2>&1); test $? -eq 1 && grep -q "no destination" <<<"$out"' _ "$CLI"
fi

PP="$OUT/altiward-forwarder-privileges-hook.mobileconfig"
check "Privileges profile is valid" plutil -lint "$PP"
check "Privileges profile pins the built hook" grep -q "<string>$(shasum -a 256 "$BIN" | cut -d' ' -f1)</string>" "$PP"
check "Privileges profile points at the installed hook" grep -q "<string>$INSTALLED_BIN</string>" "$PP"
check "settings profile is valid" plutil -lint "$OUT/altiward-forwarder-hook-settings.mobileconfig"

check "package exists" test -f "$PKG"
files="$(pkgutil --payload-files "$PKG" 2>/dev/null || true)"
for f in "$INSTALLED_BIN" "$INSTALL_DIR/Altiward Forwarder.app/Contents/MacOS/altiward-forwarder-hook" "$INSTALL_DIR/Altiward Forwarder.app/Contents/Resources/AppIcon.icns" "$INSTALL_DIR/uninstall.sh" "/Library/LaunchAgents/$AGENT_LABEL.plist"; do
  check "package installs $f" grep -qx ".$f" <<<"$files"
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
pkgutil --expand "$PKG" "$WORK/expanded" >/dev/null 2>&1 || true
check "package installs only on the system volume" grep -q 'enable_localSystem="true"' "$WORK/expanded/Distribution"
check "Installer shows the title Altiward Forwarder" grep -q '<title>Altiward Forwarder</title>' "$WORK/expanded/Distribution"
for f in altiward-forwarder-privileges-hook altiward-forwarder-hook-settings altiward-forwarder-login-items; do
  check "$f.mobileconfig is named Altiward Forwarder (…)" bash -c 'plutil -extract PayloadDisplayName raw "$1" | grep -q "^Altiward Forwarder ("' _ "$OUT/$f.mobileconfig"
done
COMPONENT="$(find "$WORK/expanded" -maxdepth 1 -name '*.pkg' | head -1)"
check "payload is owned by root:wheel" bash -c '! lsbom -p ugf "$1/Bom" | grep -qv $'"'"'^0\t0\t'"'"'' _ "$COMPONENT"
check "hook is mode 755 in the payload" bash -c 'lsbom -p mf "$1/Bom" | grep -q $'"'"'^100755\t.*/MacOS/Altiward Forwarder$'"'"'' _ "$COMPONENT"

LA="$WORK/agent.plist"
(cd "$WORK" && mkdir -p payload && cd payload && cat "$COMPONENT/Payload" | gunzip -dc | cpio -i --quiet 2>/dev/null) || true
cp "$WORK/payload/Library/LaunchAgents/$AGENT_LABEL.plist" "$LA" 2>/dev/null || true
check "LaunchAgent plist is valid" plutil -lint "$LA"
check "LaunchAgent label" test "$(plist "$LA" Label)" = "$AGENT_LABEL"
check "LaunchAgent runs --flush" test "$(plist "$LA" ProgramArguments:1)" = "--flush"
check "LaunchAgent runs the installed hook" test "$(plist "$LA" ProgramArguments:0)" = "$INSTALLED_BIN"
check "LaunchAgent is attributed to Altiward Forwarder" test "$(plist "$LA" AssociatedBundleIdentifiers:0)" = com.altiward.forwarder.hook
check "LaunchAgent runs every 5 minutes" test "$(plist "$LA" StartInterval)" = 300

SCRIPTS="$(find "$WORK/expanded" -type d -name Scripts 2>/dev/null | head -1)"
check "package has an executable postinstall" test -x "${SCRIPTS:-/missing}/postinstall"
check "postinstall succeeds on another volume, touching nothing" "${SCRIPTS:-/missing}/postinstall" "$PKG" "/" "$WORK/volume" "/"

if [ "${RELEASE:-0}" = 1 ]; then
  check "signed with Developer ID" bash -c 'codesign -d --verbose=2 "$1" 2>&1 | grep -q "Authority=Developer ID Application"' _ "$BIN"
  check "package signed with Developer ID Installer" bash -c 'pkgutil --check-signature "$1" | grep -q "Developer ID Installer"' _ "$PKG"
  check "Gatekeeper accepts the package" spctl --assess --type install "$PKG"
  check "notarization ticket stapled" xcrun stapler validate "$PKG"
fi

if [ "$failures" -gt 0 ]; then echo "$failures check(s) failed"; exit 1; fi
echo "all checks passed"
