#!/usr/bin/env python3
"""Compare workflows before and after `gh pin-actions workflows --latest --overwrite`.

Usage: check-pinned-actions.py FILE...   (HEAD is the "before", the working tree the "after")

gh-pin-actions rewrites every `uses:` it is asked to. It pins an action to a commit SHA, except
when the release is immutable: then it pins the tag (owner/repo@v1.2.3), which is just as fixed.
So a changed line is only a problem when it is not the same version as before:
  - the old ref was not a commit SHA (unpinned), or
  - the old version, from the `# vX.Y.Z` comment, differs from the new one (not the latest release).
A SHA that became the same version's tag is expected and ignored.
"""
import re
import subprocess
import sys

USES = re.compile(r"\buses:\s*(?P<action>[^@\s]+)@(?P<ref>[^\s#]+)(?:\s*#\s*(?P<comment>\S+))?")
SHA = re.compile(r"^[0-9a-f]{40}$")


def uses(text):
    return [m for m in map(USES.search, text.splitlines()) if m]


def version(m):
    return m["comment"] if SHA.match(m["ref"]) else m["ref"]


problems = []
for path in sys.argv[1:]:
    before = subprocess.run(["git", "show", f"HEAD:{path}"], capture_output=True, text=True, check=True).stdout
    after = open(path, encoding="utf-8").read()
    old, new = uses(before), uses(after)
    if len(old) != len(new):
        problems.append(f"{path}: gh-pin-actions changed the number of `uses:` lines")
        continue
    for o, n in zip(old, new):
        if o["action"].startswith(("./", "$/", "docker://")):
            continue
        if not SHA.match(o["ref"]):
            problems.append(f"{path}: {o['action']}@{o['ref']} is not pinned to a commit SHA (newest: {version(n)})")
        elif version(o) != version(n):
            problems.append(f"{path}: {o['action']} is {version(o)}, the latest release is {version(n)}")

for p in problems:
    print(f"::error::{p}")
sys.exit(1 if problems else 0)
