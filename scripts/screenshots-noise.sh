#!/usr/bin/env bash
# Tell render noise from a real change in docs/screenshots.
#
# Chrome's anti-aliasing moves a few pixels between runs. For every PNG that differs from HEAD, count
# the pixels that differ by more than a 5% colour fuzz. Up to MAX_PIXELS of them is noise: with
# `restore` the file is reset to HEAD, with `report` it is only listed. Anything above is a change.
# Needs ImageMagick's `compare` (on the runner image); without it nothing is treated as noise.
#
#   scripts/screenshots-noise.sh restore   # push to main: drop the noise before deciding to open a PR
#   scripts/screenshots-noise.sh report    # pull request: print a markdown table, change nothing
set -euo pipefail

mode="${1:-report}"
MAX_PIXELS="${SCREENSHOT_NOISE_MAX_PIXELS:-100}" # of ~1.2M pixels per image; one icon is far above this
dir=docs/screenshots

command -v compare >/dev/null || { echo "ImageMagick compare not found: treating every difference as a change." >&2; exit 0; }

old="$(mktemp --suffix=.png)"
trap 'rm -f "$old"' EXIT

[ "$mode" = report ] && printf '| Image | Pixels differing | Verdict |\n|---|---:|---|\n'

git diff --name-only -- "$dir" | while read -r f; do
  if ! git show "HEAD:$f" >"$old" 2>/dev/null; then
    [ "$mode" = report ] && printf '| `%s` | new file | change |\n' "$(basename "$f")"
    continue
  fi
  # compare prints the count on stderr and exits 1 when the images differ; a size change is an error.
  n="$(compare -metric AE -fuzz 5% "$old" "$f" null: 2>&1 || true)"
  if ! [[ "$n" =~ ^[0-9]+$ ]]; then n=-1; fi # different dimensions: always a change
  if [ "$n" -ge 0 ] && [ "$n" -le "$MAX_PIXELS" ]; then
    verdict=noise
    [ "$mode" = restore ] && { echo "Ignoring render noise in $f ($n px)"; git checkout -- "$f"; }
  else
    verdict=change
  fi
  [ "$mode" = report ] && printf '| `%s` | %s | %s |\n' "$(basename "$f")" "$n" "$verdict"
done
exit 0
