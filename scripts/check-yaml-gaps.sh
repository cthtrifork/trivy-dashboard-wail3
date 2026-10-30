#!/usr/bin/env bash
# Fails on a blank line inside a workflow step: between `uses:` and `with:`, or straight after a
# `key:` that opens a mapping. yamllint cannot express this (it only limits runs of blank lines).
# Usage: scripts/check-yaml-gaps.sh [file...]   (default: .github/workflows and .github/actions)
set -euo pipefail

if [ "$#" -eq 0 ]; then
  set -- $(git ls-files '.github/workflows/*.yml' '.github/actions/**/*.yml')
fi

status=0
for f in "$@"; do
  # A blank line followed by a deeply indented step key, or a blank line right after `key:`.
  hits=$(grep -nPzo '(?m)^[^\n]*\n\n(?= {8,}(with|env|if|id|run|timeout-minutes):)|^ {6,}[A-Za-z-]+:\n\n' "$f" | tr '\0' '\n' || true)
  if [ -n "$hits" ]; then
    echo "::error file=$f::blank line inside a step (remove it):"
    echo "$hits"
    status=1
  fi
done
exit "$status"
