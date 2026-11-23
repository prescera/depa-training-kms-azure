#!/usr/bin/env python3
"""Recompute and cross-check the app bundle digest, exactly as build_bundle.js defines it.

    bundle_digest = "sha256:" + hex(SHA-256(JCS({metadata, modules})))

where `modules` excludes the generated build_info.js module (which embeds the digest) and is
sorted by name. This is the value GET /app/info reports as `bundle_digest` and that DC members
approve with `approve_app_digest`.

Usage: bundle_digest.py <dist-dir>
Reads <dist-dir>/bundle.json and <dist-dir>/bundle_digest.txt (written by `make build`), fails
unless the recomputed digest, bundle_digest.txt and the BUNDLE_DIGEST constant inside
build_info.js all agree, then prints the digest.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

import rfc8785

BUILD_INFO = "build_info.js"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    dist = Path(sys.argv[1])
    bundle = json.loads((dist / "bundle.json").read_text(encoding="utf-8"))
    built = (dist / "bundle_digest.txt").read_text(encoding="ascii").strip()

    modules = sorted((m for m in bundle["modules"] if m["name"] != BUILD_INFO), key=lambda m: m["name"])
    digest = "sha256:" + hashlib.sha256(rfc8785.dumps({"metadata": bundle["metadata"], "modules": modules})).hexdigest()

    info = [m["module"] for m in bundle["modules"] if m["name"] == BUILD_INFO]
    embedded = re.search(r'BUNDLE_DIGEST = "(sha256:[0-9a-f]{64})"', info[0]) if len(info) == 1 else None

    problems = []
    if digest != built:
        problems.append(f"recomputed {digest} != bundle_digest.txt {built}")
    if embedded is None or embedded.group(1) != built:
        problems.append(f"{BUILD_INFO} does not embed {built}")
    if problems:
        print("bundle_digest: " + "; ".join(problems), file=sys.stderr)
        return 1
    print(digest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
