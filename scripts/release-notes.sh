#!/bin/bash
# Prints one release's section of CHANGELOG.md, the notes published with the release.
# Fails if the section is missing, still undated, or has no "### Changes".
# A relay release candidate (X.Y.Z-rc.N) takes the coming release's section, which may
# still be undated.
#
#   scripts/release-notes.sh relay 0.1.0
#   scripts/release-notes.sh relay 0.1.0-rc.1
#   scripts/release-notes.sh hook 0.1.0
set -euo pipefail

PRODUCT="${1:?relay or hook}"
VERSION="${2:?version, e.g. 0.1.0}"
case "$PRODUCT" in
  relay) TITLE="Relay" ;;
  hook) TITLE="Hook" ;;
  *) echo "product must be relay or hook, got $PRODUCT" >&2; exit 1 ;;
esac
RELEASE="$VERSION"
CANDIDATE=""
if [[ "$VERSION" =~ ^([0-9]+\.[0-9]+\.[0-9]+)-rc\.[0-9]+$ ]]; then
  [ "$PRODUCT" = relay ] || { echo "only the relay has release candidates" >&2; exit 1; }
  RELEASE="${BASH_REMATCH[1]}"
  CANDIDATE="$VERSION"
elif ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "version must be X.Y.Z, or X.Y.Z-rc.N for a relay release candidate, got $VERSION" >&2
  exit 1
fi
cd "$(dirname "$0")/.."

# The section runs from its heading to the next release heading.
SECTION="$(awk -v head="## $TITLE $RELEASE - " '
  index($0, head) == 1 { found = 1; print; next }
  found && /^## / { exit }
  found { print }
' CHANGELOG.md)"

if [ -z "$SECTION" ]; then
  echo "CHANGELOG.md has no \"## $TITLE $RELEASE - <date>\" section" >&2
  exit 1
fi
DATE="$(head -1 <<<"$SECTION" | sed "s/^## $TITLE $RELEASE - //")"
if [ -n "$CANDIDATE" ]; then
  SECTION="## $TITLE $CANDIDATE - $(date -u +%F), release candidate for $RELEASE
$(tail -n +2 <<<"$SECTION")"
elif ! [[ "$DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  echo "CHANGELOG.md: $TITLE $RELEASE is dated \"$DATE\"; put the release date (YYYY-MM-DD) before releasing" >&2
  exit 1
fi
grep -qx "### Changes" <<<"$SECTION" || { echo "CHANGELOG.md: $TITLE $RELEASE has no \"### Changes\"" >&2; exit 1; }
printf '%s\n' "$SECTION"
