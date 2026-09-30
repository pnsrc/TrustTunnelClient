#!/usr/bin/env python3
"""Print "<versionName> <versionCode>" for an Android build from a release tag.

    version_from_tag.py v0.13b   ->  0.13b 130000
    version_from_tag.py v0.13    ->  0.13 130009
    version_from_tag.py v1.2.3rc2 -> 1.2.3rc2 10020032

versionCode = major*10_000_000 + minor*10_000 + patch*10 + stage, where stage is
9 for a final release and the pre-release number (0-8) otherwise, so a final
release always sorts after its pre-releases and codes only ever grow.
"""

import re
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    tag = sys.argv[1].strip()
    m = re.fullmatch(r"[vV]?(\d+(?:\.\d+){0,2})-?([A-Za-z][A-Za-z0-9]*)?", tag)
    if not m:
        print(f"not a version tag: {tag!r}", file=sys.stderr)
        return 1
    numbers = [int(x) for x in m.group(1).split(".")] + [0, 0]
    major, minor, patch = numbers[:3]
    suffix = m.group(2) or ""
    if minor > 999 or patch > 999:
        print("minor/patch must be below 1000", file=sys.stderr)
        return 1
    stage = 9 if not suffix else min(int((re.search(r"(\d+)$", suffix) or [None, "0"])[1]), 8)
    code = major * 10_000_000 + minor * 10_000 + patch * 10 + stage
    if code > 2_100_000_000:
        print("version code too large", file=sys.stderr)
        return 1
    name = tag[1:] if tag[:1] in "vV" else tag
    print(name, code)
    return 0


if __name__ == "__main__":
    sys.exit(main())
