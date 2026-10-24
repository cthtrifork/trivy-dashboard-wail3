#!/usr/bin/env bash
# Copies freshly generated screenshots into the committed directory, but only the ones that
# changed visibly. Rendering is not bit-for-bit stable (a dialog's rounded corners can antialias
# differently between runs), so a byte comparison would rewrite files for no reason. A file is
# replaced when it is new, when its size changed, or when more than MAX_PIXELS pixels differ
# by more than FUZZ. Needs ImageMagick's `compare`.
#
# Usage: scripts/sync-screenshots.sh <new-dir> [<committed-dir>]
set -euo pipefail

new="${1:?usage: sync-screenshots.sh <new-dir> [<committed-dir>]}"
dst="${2:-docs/screenshots}"
fuzz="${FUZZ:-3%}"
max_pixels="${MAX_PIXELS:-200}"

mkdir -p "$dst"
changed=0
for f in "$new"/*.png; do
  name="$(basename "$f")"
  old="$dst/$name"
  if [ ! -f "$old" ]; then
    reason="new"
  elif cmp -s "$f" "$old"; then
    continue
  else
    # compare prints the number of differing pixels on stderr; it exits 1 when there are any
    # and 2 on an error such as a size mismatch.
    diff_px="$(compare -metric AE -fuzz "$fuzz" "$f" "$old" null: 2>&1 || true)"
    case "$diff_px" in
      '' | *[!0-9.e+]*) reason="size or format changed" ;;
      *) if [ "${diff_px%.*}" -gt "$max_pixels" ]; then reason="$diff_px pixels differ"; else continue; fi ;;
    esac
  fi
  cp "$f" "$old"
  echo "updated $name ($reason)"
  changed=$((changed + 1))
done
echo "$changed screenshot(s) updated"
