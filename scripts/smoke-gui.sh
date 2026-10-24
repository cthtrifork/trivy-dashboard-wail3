#!/usr/bin/env bash
# Smoke-tests the real GTK4 + WebKitGTK binary under a virtual display.
#
#   scripts/smoke-gui.sh <binary> [screenshot.png]
#
# It starts Xvfb, launches the app, waits for its window, waits for the embedded
# frontend to render, saves a screenshot and checks it is not blank. It fails on
# dynamic-linker errors (missing library or glibc symbol), crashes, a missing
# window, or a blank page. It is distribution-agnostic: CI runs it on Ubuntu
# (where the release is built) and inside a Fedora container.
#
# Needs: Xvfb, xwininfo (x11-utils / xorg-x11-utils) and ImageMagick (6 or 7).
# dbus-run-session is used when present.
set -euo pipefail

bin="${1:?usage: smoke-gui.sh <binary> [screenshot.png]}"
shot="${2:-smoke.png}"
title="${WINDOW_TITLE:-Trivy Scanner}"
display=":${SMOKE_DISPLAY:-99}"
timeout_s="${SMOKE_TIMEOUT:-60}"

tmp="$(mktemp -d)"
xvfb_pid=""
app_pid=""
cleanup() {
  [ -n "$app_pid" ] && kill "$app_pid" 2>/dev/null || true
  [ -n "$xvfb_pid" ] && kill "$xvfb_pid" 2>/dev/null || true
  rm -rf "${tmp:?}"
}
trap cleanup EXIT
fail() { echo "SMOKE FAIL: $*" >&2; [ -f "$tmp/app.log" ] && { echo "--- app output:" >&2; tail -30 "$tmp/app.log" >&2; }; exit 1; }

command -v "$bin" >/dev/null 2>&1 || [ -x "$bin" ] || fail "$bin is not executable"

# 1. Linker check first: this is the message users hit on a distro missing a package.
if missing="$(ldd "$bin" 2>&1 | grep -E "not found|version .* not found")"; then
  echo "$missing" >&2
  fail "the binary has unresolved dynamic dependencies on this system"
fi
echo "ldd: all dynamic dependencies resolve"

# 2. Virtual display.
Xvfb "$display" -screen 0 1280x800x24 >"$tmp/xvfb.log" 2>&1 &
xvfb_pid=$!
for _ in $(seq 1 50); do [ -e "/tmp/.X11-unix/X${display#:}" ] && break; sleep 0.1; done
[ -e "/tmp/.X11-unix/X${display#:}" ] || fail "Xvfb did not start: $(cat "$tmp/xvfb.log")"

# 3. Launch the app. A container has no user namespaces for WebKit's sandbox, no GPU and
#    no accessibility bus; these only switch off things a container cannot provide.
export DISPLAY="$display" GDK_BACKEND=x11 NO_AT_BRIDGE=1 LIBGL_ALWAYS_SOFTWARE=1 \
       WEBKIT_DISABLE_COMPOSITING_MODE=1 WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1
launcher=()
command -v dbus-run-session >/dev/null 2>&1 && launcher=(dbus-run-session --)
"${launcher[@]}" "$bin" >"$tmp/app.log" 2>&1 &
app_pid=$!

# 4. Wait for the window.
deadline=$((SECONDS + timeout_s))
until xwininfo -root -tree 2>/dev/null | grep -q "\"$title\""; do
  kill -0 "$app_pid" 2>/dev/null || fail "the app exited before showing a window"
  [ "$SECONDS" -lt "$deadline" ] || fail "no window titled \"$title\" within ${timeout_s}s"
  sleep 0.5
done
echo "window \"$title\" is on screen"

# 5. Wait for the frontend to render: the blank window has near-zero pixel variance.
#    ImageMagick 7 (Fedora) has one `magick` command; ImageMagick 6 (Ubuntu 24.04) has import/convert.
if command -v magick >/dev/null 2>&1; then
  capture() { magick import -window root "$1"; }
  stddev()  { magick "$1" -colorspace Gray -format '%[fx:standard_deviation]' info:; }
else
  capture() { import -window root "$1"; }
  stddev()  { convert "$1" -colorspace Gray -format '%[fx:standard_deviation]' info:; }
fi
variance() { capture "$1" 2>/dev/null && stddev "$1"; }
min_sd="${SMOKE_MIN_STDDEV:-0.03}"
sd=0
until awk -v s="${sd:-0}" -v m="$min_sd" 'BEGIN{exit !(s>m)}'; do
  kill -0 "$app_pid" 2>/dev/null || fail "the app exited while loading the page"
  [ "$SECONDS" -lt "$deadline" ] || fail "page still blank after ${timeout_s}s (pixel std-dev ${sd}, need > ${min_sd})"
  sleep 1
  sd="$(variance "$tmp/probe.png" || echo 0)"
done
sleep 2 # let a second paint settle, then take the real screenshot
capture "$shot"
echo "page rendered (pixel std-dev ${sd}); screenshot: $shot"

# 6. Still alive, and nothing in the output that means a broken install.
kill -0 "$app_pid" 2>/dev/null || fail "the app died after rendering"
if grep -qiE "error while loading shared libraries|symbol lookup error|GLIBC_[0-9.]+' not found|Segmentation fault|SIGSEGV|panic:" "$tmp/app.log"; then
  fail "fatal messages in the app output"
fi
echo "SMOKE OK"
